#!/usr/bin/env python3
"""
cut_transcript_supplied.py  (v2)

Cuts a video into soundboard clips using a subtitle file you already have
(.srt or .vtt from Pinokio / Whisper web UI). No transcription happens here.

What it does, per clip:
  1. MERGE    Consecutive cues are joined until the text ends a sentence
              (. ! ? ...), so a clip never ends mid-sentence. Long pauses and
              a max length stop a merge from running away.
  2. SNAP     Start/end are moved outward to the nearest real silence in the
              audio (ffmpeg silencedetect), because Whisper timestamps are
              often 100-500 ms off and clip words at the edges.
  3. NORMALIZE Two-pass EBU R128 loudnorm per clip, so every sound plays at
              the same volume. Short fades avoid clicks.
  4. EXPORT   mp3 and/or mp4 per clip, plus manifest.csv.

Requires: ffmpeg on PATH (or --ffmpeg C:\\Perm\\ffmpeg.exe)

Usage:
    python soundboard_cut_transcript_supplied.py video.mp4
    python soundboard_cut_transcript_supplied.py video.mp4 --srt subs.srt --mode both
    python soundboard_cut_transcript_supplied.py video.mp4 --no-merge --no-snap
"""

import argparse
import csv
import json
import re
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path

TS_RE = re.compile(
    r"(?:(\d+):)?(\d+):(\d+)[,.](\d+)\s*-->\s*(?:(\d+):)?(\d+):(\d+)[,.](\d+)"
)
# Text that ends a sentence, allowing closing quotes/brackets after the mark.
SENTENCE_END_RE = re.compile(r"[.!?\u2026]+[\"'\u201d\u2019)\]]*\s*$")


@dataclass
class Cue:
    start: float
    end: float
    text: str


# --------------------------------------------------------------------------
# Subtitle parsing
# --------------------------------------------------------------------------

def _secs(h, m, s, ms):
    return int(h or 0) * 3600 + int(m) * 60 + int(s) + int(ms.ljust(3, "0")[:3]) / 1000


def parse_subs(path: Path) -> list[Cue]:
    """SRT/VTT parser. Tolerates CRLF, WEBVTT header, missing indexes, no-hour stamps."""
    raw = path.read_text(encoding="utf-8-sig", errors="replace").replace("\r\n", "\n")
    cues = []
    for block in re.split(r"\n\s*\n", raw.strip()):
        lines = [l for l in block.split("\n") if l.strip()]
        for i, line in enumerate(lines):
            m = TS_RE.search(line)
            if m:
                g = m.groups()
                text = " ".join(lines[i + 1:]).strip()
                text = re.sub(r"<[^>]+>", "", text)  # strip <i>, <c> etc.
                cues.append(Cue(_secs(*g[:4]), _secs(*g[4:]), text))
                break
    return cues


# --------------------------------------------------------------------------
# 1. Merge cues into whole sentences
# --------------------------------------------------------------------------

def merge_cues(cues: list[Cue], max_gap: float, max_dur: float) -> list[Cue]:
    """
    Join cues until one ends with sentence punctuation.
    A merge is abandoned (group flushed as-is) when the next cue is more than
    max_gap seconds away, or the group would exceed max_dur seconds.
    """
    groups: list[Cue] = []
    cur: Cue | None = None
    for c in cues:
        if cur is None:
            cur = Cue(c.start, c.end, c.text)
        else:
            gap = c.start - cur.end
            too_long = (c.end - cur.start) > max_dur
            if gap > max_gap or too_long:
                groups.append(cur)
                cur = Cue(c.start, c.end, c.text)
            else:
                cur = Cue(cur.start, c.end, f"{cur.text} {c.text}".strip())
        if SENTENCE_END_RE.search(cur.text):
            groups.append(cur)
            cur = None
    if cur is not None:
        groups.append(cur)
    return groups


# --------------------------------------------------------------------------
# 2. Snap boundaries to silence
# --------------------------------------------------------------------------

def detect_silences(ff: str, src: Path, noise_db: float, min_len: float):
    """Return a list of (silence_start, silence_end) over the whole file."""
    cmd = [ff, "-hide_banner", "-i", str(src), "-vn",
           "-af", f"silencedetect=noise={noise_db}dB:d={min_len}", "-f", "null", "-"]
    err = subprocess.run(cmd, capture_output=True, text=True).stderr
    dm = re.search(r"Duration:\s*(\d+):(\d+):(\d+\.\d+)", err)
    total = int(dm[1]) * 3600 + int(dm[2]) * 60 + float(dm[3]) if dm else float("inf")

    silences, start = [], None
    for line in err.splitlines():
        if "silence_start:" in line:
            start = max(0.0, float(line.split("silence_start:")[1].split()[0]))
        elif "silence_end:" in line and start is not None:
            end = float(line.split("silence_end:")[1].split()[0])
            silences.append((start, end))
            start = None
    if start is not None:  # file ends in silence
        silences.append((start, total))
    return silences


def snap_start(t: float, silences, window: float, tol: float = 0.15) -> float:
    """Latest silence END at or before t (+tol), within window. That is where speech begins."""
    best = None
    for s, e in silences:
        if t - window <= e <= t + tol:
            best = e if best is None or e > best else best
    return best if best is not None else t


def snap_end(t: float, silences, window: float, tol: float = 0.15) -> float:
    """Earliest silence START at or after t (-tol), within window. That is where speech ends."""
    best = None
    for s, e in silences:
        if t - tol <= s <= t + window:
            best = s if best is None or s < best else best
    return best if best is not None else t


# --------------------------------------------------------------------------
# 3. Loudness normalization (two-pass loudnorm)
# --------------------------------------------------------------------------

def measure_loudness(ff, src, start, dur, lufs, tp, lra):
    """Pass 1: measure the exact segment. Returns a dict or None (e.g. silent clip).
    -t must sit BEFORE -i: loudnorm looks ahead ~3s, and an output-side -t lets it
    read (and measure) audio past the clip end, which skews the result."""
    cmd = [ff, "-hide_banner", "-ss", f"{start:.3f}", "-t", f"{dur:.3f}", "-i", str(src),
           "-vn", "-af", f"loudnorm=I={lufs}:TP={tp}:LRA={lra}:print_format=json",
           "-f", "null", "-"]
    err = subprocess.run(cmd, capture_output=True, text=True).stderr
    blocks = re.findall(r"\{[^{}]*\}", err)
    if not blocks:
        return None
    try:
        d = json.loads(blocks[-1])
        if float(d["input_i"]) == float("-inf"):
            return None
        return d
    except (ValueError, KeyError):
        return None


def audio_filter(ff, src, start, dur, a) -> str:
    """Build the -af chain: loudnorm (measured) + short fades. Empty string if disabled."""
    chain = []
    if a.normalize:
        m = measure_loudness(ff, src, start, dur, a.lufs, a.tp, a.lra)
        if m:
            chain.append(
                f"loudnorm=I={a.lufs}:TP={a.tp}:LRA={a.lra}"
                f":measured_I={m['input_i']}:measured_TP={m['input_tp']}"
                f":measured_LRA={m['input_lra']}:measured_thresh={m['input_thresh']}"
                f":offset={m['target_offset']}:linear=true"
            )
        else:
            print("  (could not measure loudness, falling back to single-pass)")
            chain.append(f"loudnorm=I={a.lufs}:TP={a.tp}:LRA={a.lra}")
    if a.fade > 0 and dur > a.fade * 2:
        chain.append(f"afade=t=in:d={a.fade}")
        chain.append(f"afade=t=out:st={dur - a.fade:.3f}:d={a.fade}")
    return ",".join(chain)


# --------------------------------------------------------------------------
# 4. Export
# --------------------------------------------------------------------------

def run(cmd: list[str]) -> bool:
    r = subprocess.run(cmd, capture_output=True, text=True)
    if r.returncode != 0:
        print(r.stderr[-500:], file=sys.stderr)
    return r.returncode == 0


def cut_audio(ff, src, dst, start, dur, af, bitrate):
    cmd = [ff, "-y", "-ss", f"{start:.3f}", "-t", f"{dur:.3f}", "-i", str(src), "-vn"]
    if af:
        cmd += ["-af", af]
    # loudnorm resamples internally to 192k, so force a sane output rate
    cmd += ["-ar", "44100", "-c:a", "libmp3lame", "-b:a", bitrate, str(dst)]
    return run(cmd)


def cut_video(ff, src, dst, start, dur, af, crf):
    # Re-encode so the cut lands exactly on the timestamp, not the nearest keyframe.
    cmd = [ff, "-y", "-ss", f"{start:.3f}", "-t", f"{dur:.3f}", "-i", str(src),
           "-c:v", "libx264", "-preset", "veryfast", "-crf", str(crf)]
    if af:
        cmd += ["-af", af]
    cmd += ["-ar", "48000", "-c:a", "aac", "-b:a", "192k", "-movflags", "+faststart", str(dst)]
    return run(cmd)


def slug(text: str, max_words: int = 6, max_len: int = 40) -> str:
    words = re.sub(r"[^\w\s-]", "", text.lower()).split()[:max_words]
    return "_".join(words)[:max_len].strip("_") or "clip"


# --------------------------------------------------------------------------
# Main
# --------------------------------------------------------------------------

def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("video", type=Path)
    ap.add_argument("--srt", type=Path, help="subtitle file (.srt/.vtt). Default: same name as video")
    ap.add_argument("--out", type=Path, help="output folder (default: <video>_clips)")
    ap.add_argument("--mode", choices=["audio", "video", "both"], default="audio")
    ap.add_argument("--ffmpeg", default="ffmpeg", help="path to ffmpeg")

    g = ap.add_argument_group("sentence merging")
    g.add_argument("--no-merge", action="store_true", help="one clip per subtitle cue")
    g.add_argument("--max-gap", type=float, default=1.5, help="don't merge across pauses longer than this (s)")
    g.add_argument("--max-dur", type=float, default=15.0, help="max merged clip length (s)")

    g = ap.add_argument_group("boundary snapping")
    g.add_argument("--no-snap", action="store_true", help="use raw subtitle timestamps")
    g.add_argument("--snap-window", type=float, default=0.6, help="how far to search for silence (s)")
    g.add_argument("--silence-db", type=float, default=-35, help="silence threshold; raise toward -25 for noisy audio")
    g.add_argument("--silence-min", type=float, default=0.12, help="min silence length to count (s)")
    g.add_argument("--pad-before", type=float, default=0.05, help="extra lead-in after snapping (s)")
    g.add_argument("--pad-after", type=float, default=0.10, help="extra tail after snapping (s)")

    g = ap.add_argument_group("loudness")
    g.add_argument("--no-normalize", action="store_true")
    g.add_argument("--lufs", type=float, default=-16, help="target integrated loudness")
    g.add_argument("--tp", type=float, default=-1.5, help="true peak ceiling (dBTP)")
    g.add_argument("--lra", type=float, default=11, help="loudness range")
    g.add_argument("--fade", type=float, default=0.015, help="fade in/out length (s), 0 to disable")

    g = ap.add_argument_group("encoding")
    g.add_argument("--min-dur", type=float, default=0.4, help="skip clips shorter than this (s)")
    g.add_argument("--bitrate", default="192k", help="mp3 bitrate")
    g.add_argument("--crf", type=int, default=20, help="x264 quality (lower = better)")
    a = ap.parse_args()
    a.normalize = not a.no_normalize
    ff = a.ffmpeg

    if not a.video.exists():
        sys.exit(f"Not found: {a.video}")
    srt = a.srt or next((a.video.with_suffix(e) for e in (".srt", ".vtt")
                         if a.video.with_suffix(e).exists()), None)
    if srt is None or not srt.exists():
        sys.exit("No subtitle file found. Pass --srt, or put a .srt/.vtt next to the video.")

    cues = parse_subs(srt)
    if not cues:
        sys.exit("No cues found in subtitle file.")

    # --- merge ---
    if a.no_merge:
        groups = cues
    else:
        if not any(SENTENCE_END_RE.search(c.text) for c in cues):
            print("Warning: no sentence punctuation in subtitles; merging falls back to pause length only.")
        groups = merge_cues(cues, a.max_gap, a.max_dur)
    print(f"{len(cues)} cues -> {len(groups)} clips")

    # --- snap ---
    silences = []
    if not a.no_snap:
        print("Detecting silences...")
        silences = detect_silences(ff, a.video, a.silence_db, a.silence_min)
        print(f"  {len(silences)} silent gaps found")

    out = a.out or a.video.with_name(a.video.stem + "_clips")
    if a.mode in ("audio", "both"):
        (out / "audio").mkdir(parents=True, exist_ok=True)
    if a.mode in ("video", "both"):
        (out / "video").mkdir(parents=True, exist_ok=True)

    manifest, done, failed, skipped = [], 0, 0, 0
    for i, c in enumerate(groups, 1):
        start = snap_start(c.start, silences, a.snap_window) if silences else c.start
        end = snap_end(c.end, silences, a.snap_window) if silences else c.end
        start -= a.pad_before
        end += a.pad_after

        # Never reach past the midpoint of the gap to a neighbor (avoids bleeding in other speech).
        if i > 1:
            start = max(start, (groups[i - 2].end + c.start) / 2)
        if i < len(groups):
            end = min(end, (c.end + groups[i].start) / 2)
        start = max(0.0, start)
        dur = end - start

        if dur < a.min_dur:
            skipped += 1
            continue

        name = f"{i:03}_{slug(c.text)}"
        af = audio_filter(ff, a.video, start, dur, a)

        ok = True
        if a.mode in ("audio", "both"):
            ok &= cut_audio(ff, a.video, out / "audio" / f"{name}.mp3", start, dur, af, a.bitrate)
        if a.mode in ("video", "both"):
            ok &= cut_video(ff, a.video, out / "video" / f"{name}.mp4", start, dur, af, a.crf)

        done += ok
        failed += not ok
        manifest.append([name, f"{start:.3f}", f"{end:.3f}", f"{dur:.3f}", c.text])
        print(f"[{'ok' if ok else 'FAIL'}] {name}  ({dur:.2f}s)")

    with (out / "manifest.csv").open("w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(["name", "start", "end", "duration", "text"])
        w.writerows(manifest)

    print(f"\nDone: {done}  Failed: {failed}  Skipped (too short): {skipped}\nOutput: {out}")


if __name__ == "__main__":
    main()