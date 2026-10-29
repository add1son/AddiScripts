"""
Batch convert .wav to .mp3 with ffmpeg.

- Prerequisite: ffmpeg installed to path on Windows (can be done via winget install ffmpeg)
- Strips a trailing long numeric ID from each filename (e.g. "_1552438893230555207")
- Avoids overwriting: if the cleaned name already exists (on disk or from an
  earlier file in this run), appends 1, 2, 3... until it is unique
- Writes output to an "mp3_out" subfolder; originals are never touched
 
Usage:
    python wav2mp3.py "C:\\path\\to\\wavs"
    python wav2mp3.py "C:\\path\\to\\wavs" --bitrate 320k --recursive
"""
import argparse
import re
import shutil
import subprocess
import sys
from pathlib import Path
 
# Matches an optional separator plus 10+ digits at the end of the stem
TRAILING_ID = re.compile(r"[\s_\-]*\d{10,}$")
 
 
def clean_stem(stem: str) -> str:
    """Remove the trailing numeric ID. Falls back to 'audio' if nothing is left."""
    cleaned = TRAILING_ID.sub("", stem).strip(" _-")
    return cleaned or "audio"
 
 
def unique_path(out_dir: Path, stem: str, taken: set) -> Path:
    """Return out_dir/stem.mp3, or stem1.mp3, stem2.mp3... if already used."""
    candidate = out_dir / f"{stem}.mp3"
    n = 0
    while candidate.exists() or candidate.name.lower() in taken:
        n += 1
        candidate = out_dir / f"{stem}{n}.mp3"
    taken.add(candidate.name.lower())
    return candidate
 
 
def convert(src: Path, dst: Path, bitrate: str) -> bool:
    cmd = [
        "ffmpeg", "-y", "-loglevel", "error",
        "-i", str(src),
        "-codec:a", "libmp3lame", "-b:a", bitrate,
        str(dst),
    ]
    result = subprocess.run(cmd, capture_output=True, text=True)
    if result.returncode != 0:
        print(f"  FAILED: {result.stderr.strip()}")
        return False
    return True
 
 
def main():
    parser = argparse.ArgumentParser(description="Batch WAV to MP3 with ID stripping")
    parser.add_argument("folder", type=Path, help="Folder containing .wav files")
    parser.add_argument("--bitrate", default="192k", help="MP3 bitrate (default 192k)")
    parser.add_argument("--recursive", action="store_true", help="Include subfolders")
    args = parser.parse_args()
 
    if not shutil.which("ffmpeg"):
        sys.exit("ffmpeg not found on PATH. Install it first (e.g. winget install ffmpeg).")
    if not args.folder.is_dir():
        sys.exit(f"Not a folder: {args.folder}")
 
    out_dir = args.folder / "mp3_out"
    out_dir.mkdir(exist_ok=True)
 
    pattern = "**/*" if args.recursive else "*"
    wavs = sorted(
        p for p in args.folder.glob(pattern)
        if p.suffix.lower() == ".wav" and out_dir not in p.parents
    )
    if not wavs:
        sys.exit("No .wav files found.")
 
    taken = set()  # lowercase names claimed during this run
    ok = failed = 0
    for src in wavs:
        dst = unique_path(out_dir, clean_stem(src.stem), taken)
        print(f"{src.name} -> {dst.name}")
        if convert(src, dst, args.bitrate):
            ok += 1
        else:
            failed += 1
            taken.discard(dst.name.lower())
 
    print(f"\nDone. {ok} converted, {failed} failed. Output: {out_dir}")
 
 
if __name__ == "__main__":
    main()