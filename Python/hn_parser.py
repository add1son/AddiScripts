import urllib.request
import json
import time
import datetime
import os
import argparse
import sys

def fetch_hn_item(item_id: int) -> dict:
    """Fetches metadata for a given Hacker News item ID via Firebase API."""
    url = f"https://hacker-news.firebaseio.com/v0/item/{item_id}.json"
    try:
        with urllib.request.urlopen(url) as response:
            return json.loads(response.read().decode())
    except Exception as e:
        print(f"Error fetching ID {item_id}: {e}")
        return {}

def read_ids_from_file(filepath: str) -> list[int]:
    """Reads a text file and returns a list of integer IDs, ignoring invalid lines."""
    ids = []
    try:
        with open(filepath, 'r', encoding='utf-8') as f:
            for line in f:
                stripped = line.strip()
                if stripped.isdigit():
                    ids.append(int(stripped))
                elif stripped:
                    print(f"Skipping invalid ID format: {stripped}")
    except FileNotFoundError:
        print(f"Error: Input file '{filepath}' not found.")
        sys.exit(1)
    return ids

def main():
    parser = argparse.ArgumentParser(description="Generate a markdown file of Hacker News links from a text file of IDs.")
    parser.add_argument("input_file", help="Path to the text file containing Hacker News IDs (one per line).")
    parser.add_argument("-o", "--output", default="hn_links.md", help="Optional: Output markdown file path.")
    args = parser.parse_args()

    item_ids = read_ids_from_file(args.input_file)
    
    if not item_ids:
        print("No valid IDs found to process. Exiting.")
        sys.exit(0)

    print(f"Processing {len(item_ids)} Hacker News IDs from '{args.input_file}'...")
    
    output_filepath = os.path.join(os.getcwd(), args.output)
    
    with open(output_filepath, "w", encoding="utf-8") as f:
        f.write("# Hacker News Links\n\n")
        
        for item_id in item_ids:
            data = fetch_hn_item(item_id)
            if not data:
                continue
                
            title = data.get("title", "No Title Provided")
            article_url = data.get("url", "No external URL")
            comments_url = f"https://news.ycombinator.com/item?id={item_id}"
            
            # Extract and format timestamp
            timestamp = data.get("time")
            if timestamp:
                post_date = datetime.datetime.fromtimestamp(timestamp, tz=datetime.timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')
            else:
                post_date = "Unknown Date"
            
            # Write to markdown , currently using all fields
            f.write(f"### {title}\n")
            f.write(f"- **ID:** {item_id}\n")
            f.write(f"- **Date Posted:** {post_date}\n")
            f.write(f"- **Article:** <{article_url}>\n")
            f.write(f"- **Comments:** <{comments_url}>\n\n")
            
            # 100ms delay for API rate limits
            time.sleep(0.1)
            
    print(f"Export complete. File saved at: {output_filepath}")

if __name__ == "__main__":
    main()