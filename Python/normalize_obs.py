#!/usr/bin/env python3
"""Normalize and mix multi-track OBS MKV audio into a mono 16 kHz WAV for transcription.

Requires ffmpeg and ffprobe on PATH (ffmpeg 4.4+ for amix normalize=0).
"""
import argparse
import json
import subprocess
import sys
from pathlib import Path


def probe_audio_streams(path: Path) -> list:
    """Return the audio streams ffprobe finds in the file."""
    cmd = ["ffprobe", "-v", "error", "-select_streams", "a",
           "-show_entries", "stream=index,channels", "-of", "json", str(path)]
    out = subprocess.run(cmd, capture_output=True, text=True, check=True).stdout
    return json.loads(out)["streams"]


def track_chain(args) -> str:
    """Per-track cleanup: mono, rumble cut, optional denoise, leveling, loudness target."""
    parts = ["aformat=channel_layouts=mono", f"highpass=f={args.highpass}"]
    if args.denoise:
        parts.append("afftdn=nf=-25")
    if args.dynamic:
        # Evens out sections where the level jumps around
        parts.append("dynaudnorm=f=150:g=15:p=0.9")
    parts.append(f"loudnorm=I={args.target}:TP=-1.5:LRA=11")
    return ",".join(parts)


def build_filter(n_streams: int, args) -> str:
    chain = track_chain(args)
    fmt = "aformat=sample_rates=16000:channel_layouts=mono"
    if n_streams < 2:
        return f"[0:a:0]{chain},{fmt}[out]"
    return (
        f"[0:a:{args.desktop_track}]{chain},volume={args.desktop_gain}dB[d];"
        f"[0:a:{args.mic_track}]{chain},volume={args.mic_gain}dB[m];"
        f"[d][m]amix=inputs=2:normalize=0:duration=longest,"
        f"loudnorm=I={args.target}:TP=-1.5:LRA=11,{fmt}[out]"
    )


def process(src: Path, outdir: Path, args) -> None:
    streams = probe_audio_streams(src)
    if not streams:
        print(f"[skip] no audio streams: {src.name}")
        return
    if len(streams) < 2:
        print(f"[warn] only 1 audio stream in {src.name}, normalizing it alone")
    elif max(args.desktop_track, args.mic_track) >= len(streams):
        print(f"[skip] track index out of range for {src.name} ({len(streams)} streams)")
        return

    dst = outdir / f"{src.stem}_norm.wav"
    cmd = ["ffmpeg", "-y", "-hide_banner", "-loglevel", "error", "-i", str(src),
           "-filter_complex", build_filter(len(streams), args),
           "-map", "[out]", "-c:a", "pcm_s16le", str(dst)]
    subprocess.run(cmd, check=True)
    print(f"[ok] {src.name} -> {dst}")


def main() -> int:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("inputs", nargs="+", type=Path, help="MKV files or folders containing them")
    p.add_argument("-o", "--outdir", type=Path, default=Path("normalized"))
    p.add_argument("--desktop-track", type=int, default=0, help="0-based audio stream index (default 0)")
    p.add_argument("--mic-track", type=int, default=1, help="0-based audio stream index (default 1)")
    p.add_argument("--desktop-gain", type=float, default=0.0, help="extra dB on desktop before mixing")
    p.add_argument("--mic-gain", type=float, default=0.0, help="extra dB on mic before mixing")
    p.add_argument("--target", type=float, default=-16.0, help="LUFS target (default -16)")
    p.add_argument("--highpass", type=int, default=80, help="high-pass cutoff in Hz")
    p.add_argument("--denoise", action="store_true", help="apply afftdn noise reduction")
    p.add_argument("--dynamic", action="store_true", help="apply dynaudnorm for uneven levels")
    args = p.parse_args()

    files = []
    for item in args.inputs:
        files += sorted(item.glob("*.mkv")) if item.is_dir() else [item]

    args.outdir.mkdir(parents=True, exist_ok=True)
    for f in files:
        try:
            process(f, args.outdir, args)
        except subprocess.CalledProcessError as e:
            print(f"[fail] {f.name}: {e}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())