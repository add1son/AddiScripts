import os
import shutil
from datetime import datetime
from pathlib import Path

def get_media_date(file_path: Path) -> str:
    """
    Retrieves the modification time of the file to use as the sorting date.
    Returns the date formatted as YYYY-MM-DD.
    Note: For true EXIF/metadata extraction (if OS timestamps are stripped), 
    you would integrate 'exifread' for photos or 'ffmpeg-python' for videos here.
    """
    timestamp = file_path.stat().st_mtime
    return datetime.fromtimestamp(timestamp).strftime('%Y-%m-%d')

def organize_media_by_date(source_directory: str) -> None:
    """
    Scans the source directory, creates date-based subfolders, 
    and moves media files into their respective folders.
    """
    source_path = Path(source_directory)
    
    if not source_path.is_dir():
        print(f"[!] Error: The directory '{source_directory}' does not exist.")
        return

    # Define the media types to process. Adjust as needed for your edit.
    target_extensions = {'.mp4', '.mov', '.mkv', '.avi', '.jpg', '.jpeg', '.png', '.wav', '.mp3'}
    
    moved_count = 0

    for file_path in source_path.iterdir():
        if file_path.is_file() and file_path.suffix.lower() in target_extensions:
            
            # 1. Determine the folder name based on the file date
            folder_name = get_media_date(file_path)
            dest_folder = source_path / folder_name
            
            # 2. Create the destination folder if it doesn't exist
            dest_folder.mkdir(parents=True, exist_ok=True)
            
            dest_file_path = dest_folder / file_path.name
            
            # 3. Handle filename collisions
            counter = 1
            while dest_file_path.exists():
                dest_file_path = dest_folder / f"{file_path.stem}_{counter}{file_path.suffix}"
                counter += 1

            # 4. Move the file
            try:
                shutil.move(str(file_path), str(dest_file_path))
                print(f"[+] Moved: {file_path.name} -> {folder_name}\\")
                moved_count += 1
            except Exception as e:
                print(f"[-] Failed to move {file_path.name}: {e}")

    print(f"\nOperation complete. Successfully sorted {moved_count} media files.")

if __name__ == "__main__":
    # Update this path to the folder containing your media
    TARGET_MEDIA_FOLDER = r"C:\path"
    
    organize_media_by_date(TARGET_MEDIA_FOLDER)
