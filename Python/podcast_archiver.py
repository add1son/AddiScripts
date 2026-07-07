# Version Info 
# V1.3 - 06/12/2026 , 1200 PST

import os
import re
import sys
import time
import requests
import feedparser
from mutagen.easyid3 import EasyID3
from mutagen.mp3 import MP3, HeaderNotFoundError
from mutagen.id3 import ID3, COMM, ID3NoHeaderError

# ==============================================================================
# INTERACTIVE INITIALIZATION (Strict User Input)
# ==============================================================================
print("=" * 60)
print("          UNIVERSAL PODCAST ARCHIVER & PLEX TAGGER          ")
print("=" * 60)

while True:
    SHOW_NAME = input("Enter the Show Name: ").strip()
    if SHOW_NAME:
        break
    print("[!] Error: Show Name cannot be blank.")

while True:
    RSS_URL = input("Enter the RSS Feed URL: ").strip()
    if RSS_URL:
        break
    print("[!] Error: RSS Feed URL cannot be blank.")

BASE_DOWNLOAD_DIR = os.path.join(os.path.expanduser("~"), "Downloads")
clean_folder_name = re.sub(r'[\\/*?:"<>|]', "", SHOW_NAME).replace(" ", "")
OUTPUT_DIR = os.path.join(BASE_DOWNLOAD_DIR, f"{clean_folder_name}_Archive")

print("-" * 60)
print(f"Target Show : {SHOW_NAME}")
print(f"Target RSS  : {RSS_URL}")
print(f"Output Path : {OUTPUT_DIR}")
print("=" * 60)
print()
# ==============================================================================

def clean_title(title):
    """Removes illegal filesystem characters for pristine path creation."""
    cleaned = re.sub(r'[\\/*?:"<>|]', "", title)
    return cleaned.replace("â€“", "-").replace("â€”", "-").strip()

def is_rerun(title, description):
    """Scans fields for archival/rerun indicators."""
    text_to_check = f"{title} {description}".lower()
    rerun_keywords = ["rerun", "re-run", "from the archives", "archive piece", "originally aired", "encore presentation"]
    return any(keyword in text_to_check for keyword in rerun_keywords)

def download_file_with_retry(url, destination_path, max_retries=3):
    """Downloads a file stream with explicit timeout protection and retry loops."""
    headers = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64)'}
    
    for attempt in range(1, max_retries + 1):
        try:
            response = requests.get(url, stream=True, headers=headers, timeout=(10, 30))
            response.raise_for_status()
            
            total_size = int(response.headers.get('content-length', 0))
            block_size = 1024 * 1024  # 1 MB data blocks
            downloaded = 0
            
            with open(destination_path, 'wb') as f:
                for chunk in response.iter_content(chunk_size=block_size):
                    if chunk:
                        f.write(chunk)
                        downloaded += len(chunk)
                        if total_size > 0:
                            percent = (downloaded / total_size) * 100
                            sys.stdout.write(f"\r    â†³ Downloading: {percent:.1f}% ({downloaded / (1024*1024):.1f}MB / {total_size / (1024*1024):.1f}MB)")
                        else:
                            sys.stdout.write(f"\r    â†³ Downloading: {downloaded / (1024*1024):.1f}MB")
                        sys.stdout.flush()
            print()
            return True
            
        except (requests.exceptions.RequestException, requests.exceptions.Timeout) as e:
            print(f"\n    [WARNING] Attempt {attempt}/{max_retries} failed: Network timeout/drop.")
            if attempt < max_retries:
                sleep_time = attempt * 3
                print(f"    Resting {sleep_time}s before running next request...")
                time.sleep(sleep_time)
            else:
                print(f"    [ERROR] Max network retries exhausted for this target asset.")
                raise e

def is_valid_mp3(file_path):
    """Structural verification to catch completely empty files or raw non-audio HTML text."""
    if not os.path.exists(file_path) or os.path.getsize(file_path) < 1024:
        return False
    try:
        # Check if the file contains readable audio frame formats
        MP3(file_path)
        return True
    except HeaderNotFoundError:
        # File has zero valid MP3 audio frames (likely a cloaked HTML error page)
        return False
    except Exception:
        # File lacks an ID3 header shell but may still contain valid un-tagged MP3 audio
        return True

def tag_file(file_path, info):
    """Bakes advanced ID3 tags inside the completed download asset, auto-initializing headers if missing."""
    # Step 1: Structural ID3 Header Verification and Auto-Initialization
    try:
        raw_tags = ID3(file_path)
    except ID3NoHeaderError:
        # File has valid audio frames but absolutely no ID3 metadata shell yet. Build it.
        raw_tags = ID3()
        raw_tags.save(file_path)
    except Exception as e:
        raise ValueError(f"Structural metadata stream failure: {e}")

    # Step 2: Handle standard text tags via EasyID3
    audio = EasyID3(file_path)
    audio['album'] = f"{SHOW_NAME} (Season {info['year']})"
    audio['albumartist'] = SHOW_NAME
    audio['artist'] = SHOW_NAME
    audio['title'] = info['clean_ep_title']
    audio['tracknumber'] = info['track_num']
    audio['genre'] = 'Podcast'
    
    p_date = info['pub_date_parsed']
    if p_date:
        audio['date'] = f"{p_date.tm_year}-{p_date.tm_mon:02d}-{p_date.tm_mday:02d}"
    else:
        audio['date'] = info['year']
    audio.save()

    # Step 3: Use raw ID3 frame mapping to force bake the episode description field safely
    clean_summary = re.sub(r'<[^>]+>', '', info['raw_summary']).strip()
    if clean_summary:
        raw_tags = ID3(file_path)
        raw_tags.add(COMM(encoding=3, lang='eng', desc='Description', text=[clean_summary[:500]]))
        raw_tags.save()

def main():
    print(f"Connecting to target timeline: {RSS_URL}...")
    feed = feedparser.parse(RSS_URL)
    if not feed.entries:
        print("CRITICAL: Failed to download or parse RSS map.")
        return

    entries = list(reversed(feed.entries))
    print(f"Feed parsed. Processing {len(entries)} total items from core history...\n")
    
    yearly_counters = {}
    skipped_count = 0
    processed_count = 0
    failed_episodes = []

    for index, entry in enumerate(entries, start=1):
        raw_title = entry.get("title", f"Untitled Episode {index}")
        audio_url = None
        
        for enclosure in entry.get("enclosures", []):
            if enclosure.get("type", "").startswith("audio/") or enclosure.get("url", "").endswith(".mp3"):
                audio_url = enclosure.get("url")
                break
                
        if not audio_url:
            continue
            
        pub_date = entry.get("published_parsed")
        year = str(pub_date.tm_year) if pub_date else "UnknownYear"
        
        yearly_counters[year] = yearly_counters.get(year, 0) + 1
        season_ep = f"S{year}E{yearly_counters[year]:02d}"
        clean_ep_title = clean_title(raw_title)
        
        rerun_suffix = " (Rerun)" if is_rerun(raw_title, entry.get("summary", "")) else ""
        new_filename = f"{SHOW_NAME} - {season_ep} - {clean_ep_title}{rerun_suffix}.mp3"
        
        season_folder = os.path.join(OUTPUT_DIR, f"Season {year}")
        target_file_path = os.path.join(season_folder, new_filename)
        
        episode_info = {
            "year": year,
            "track_num": str(yearly_counters[year]),
            "clean_ep_title": clean_ep_title,
            "pub_date_parsed": pub_date,
            "raw_summary": entry.get("summary", "")
        }

        print(f"[{index}/{len(entries)}] Checking {season_ep}: {clean_ep_title}")

        if os.path.exists(target_file_path):
            if is_valid_mp3(target_file_path):
                print(f"  --> File exists and verified. Skipping safely.")
                skipped_count += 1
                continue
            else:
                print(f"  --> Found corrupt/incomplete local file chunk. Evacuating asset and refetching...")
                os.remove(target_file_path)

        try:
            os.makedirs(season_folder, exist_ok=True)
            
            # 1. Run the retry-capable download stream
            download_file_with_retry(audio_url, target_file_path)
            
            # 2. Structural safety checkpoint verification
            if not is_valid_mp3(target_file_path):
                raise ValueError("Downloaded file data contains invalid or non-MP3 payload stream elements (Check for server redirects).")
            
            # 3. Commit metadata injection safely
            tag_file(target_file_path, episode_info)
            processed_count += 1
            time.sleep(0.5)
            
        except Exception as e:
            print(f"  [SKIPPED ERROR] Failed item '{season_ep}': {e}")
            failed_episodes.append(f"{season_ep} - {clean_ep_title}")
            if os.path.exists(target_file_path):
                os.remove(target_file_path)

    print(f"\nProcessing Run Complete!")
    print(f"  â€¢ Newly Downloaded & Tagged: {processed_count}")
    print(f"  â€¢ Safely Skipped (Already Sorted): {skipped_count}")
    
    if failed_episodes:
        print(f"\n[!] The following {len(failed_episodes)} tracks had persistent errors and were skipped:")
        for track in failed_episodes:
            print(f"    - {track}")
        print("You can rerun the script at any time to attempt fetching these specific items again.")

if __name__ == "__main__":
    main()
