#!/usr/bin/env python3
"""
trim_clip.py
Trim a clip (mp3/mp4/anything ffmpeg reads) between two timestamps.

Timestamps: SS, SS.ms, MM:SS, MM:SS.ms or HH:MM:SS.ms
Omit --start to begin at 0, omit --end to run to the end of the file.

Audio files are stream-copied (no quality loss, frame-accurate to ~26 ms for mp3).
Video files are re-encoded so the cut is exact, because stream copy snaps to
keyframes and on a short clip that can be a second or more off. Use --copy to
force stream copy on video anyway (fast, but imprecise).

Requires: ffmpeg on PATH (or --ffmpeg C:\\Perm\\ffmpeg.exe)

Usage:
    python trim_clip.py clip.mp4 --start 0.4 --end 2.1
    python trim_clip.py clip.mp3 --start 00:00:00.25 --end 1.8 --inplace
    python trim_clip.py clip.mp4 --start 1.2            # 1.2s to end
"""

import argparse
import shutil
import subprocess
import sys
from pathlib import Path

AUDIO_EXT = {".mp3", ".wav", ".flac", ".m4a", ".aac", ".ogg", ".opus"}


def to_seconds(ts: str) -> float:
    """Parse SS / MM:SS / HH:MM:SS (each with optional decimals) into seconds."""
    parts = ts.strip().split(":")
    if not 1 <= len(parts) <= 3:
        raise argparse.ArgumentTypeError(f"bad timestamp: {ts}")
    try:
        total = 0.0
        for p in parts:
            total = total * 60 + float(p)
    except ValueError:
        raise argparse.ArgumentTypeError(f"bad timestamp: {ts}")
    return total


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("file", type=Path)
    ap.add_argument("--start", type=to_seconds, default=0.0)
    ap.add_argument("--end", type=to_seconds, default=None)
    ap.add_argument("--out", type=Path, help="output path (default: <name>_trim.<ext>)")
    ap.add_argument("--inplace", action="store_true", help="replace the original (keeps <name>.orig<ext>)")
    ap.add_argument("--copy", action="store_true", help="stream copy even for video")
    ap.add_argument("--crf", type=int, default=20, help="x264 quality for video re-encode")
    ap.add_argument("--ffmpeg", default="ffmpeg")
    a = ap.parse_args()

    if not a.file.exists():
        sys.exit(f"Not found: {a.file}")
    if a.end is not None and a.end <= a.start:
        sys.exit("--end must be after --start")

    is_audio = a.file.suffix.lower() in AUDIO_EXT
    out = a.out or a.file.with_name(f"{a.file.stem}_trim{a.file.suffix}")
    if a.inplace:
        out = a.file.with_name(f"{a.file.stem}.__tmp{a.file.suffix}")

    # -ss/-t before -i = input-side seek, fast and exact when re-encoding.
    cmd = [a.ffmpeg, "-y", "-ss", f"{a.start:.3f}"]
    if a.end is not None:
        cmd += ["-t", f"{a.end - a.start:.3f}"]
    cmd += ["-i", str(a.file)]
    if is_audio or a.copy:
        cmd += ["-c", "copy"]
    else:
        cmd += ["-c:v", "libx264", "-preset", "veryfast", "-crf", str(a.crf),
                "-c:a", "aac", "-b:a", "192k", "-movflags", "+faststart"]
    cmd.append(str(out))

    r = subprocess.run(cmd, capture_output=True, text=True)
    if r.returncode != 0:
        print(r.stderr[-600:], file=sys.stderr)
        sys.exit("ffmpeg failed")

    if a.inplace:
        backup = a.file.with_name(f"{a.file.stem}.orig{a.file.suffix}")
        shutil.move(a.file, backup)
        shutil.move(out, a.file)
        out = a.file
        print(f"Original kept as {backup}")
    print(f"Done: {out}")


if __name__ == "__main__":
    main()