import json
from bs4 import BeautifulSoup

def parse_telegram_html(html_filepath):
    """
    Parses a combined Telegram export HTML file and extracts message data.
    """
    print(f"Reading and parsing {html_filepath}...")
    with open(html_filepath, "r", encoding="utf-8") as file:
        soup = BeautifulSoup(file, "html.parser")

    messages = []
    message_divs = soup.find_all("div", class_="message")

    for message in message_divs:
        body = message.find("div", class_="body")
        if not body:
            continue

        from_name_div = body.find("div", class_="from_name")
        text_div = body.find("div", class_="text")
        date_div = body.find("div", class_="pull_right date details")

        # Extract values safely
        from_name = from_name_div.get_text(strip=True) if from_name_div else None
        text = text_div.get_text(strip=True) if text_div else None
        date = date_div["title"] if date_div and "title" in date_div.attrs else None
        time = date_div.get_text(strip=True) if date_div else None

        # Optimization: Drop empty/system notifications immediately during extraction
        if from_name is None and text is None:
            continue

        messages.append({
            "from_name": from_name,
            "text": text,
            "date": date,
            "time": time
        })

    return messages


def process_and_clean_messages(messages):
    """
    Fixes consecutive messages from the same user by forward-filling 
    missing 'from_name' values.
    """
    if not messages:
        return messages

    print("Forward-filling missing sender names for sequential messages...")
    # Start loop from index 1 since index 0 has no predecessor
    for i in range(1, len(messages)):
        if messages[i]["from_name"] is None and messages[i]["text"] is not None:
            messages[i]["from_name"] = messages[i - 1]["from_name"]
            
    return messages


def main():
    # Define file paths
    input_html = "combined.html"
    output_json = "messages_cleaned.json"

    try:
        # Step 1: Parse the raw HTML export
        raw_messages = parse_telegram_html(input_html)
        
        # Step 2: Clean and forward-fill names
        final_messages = process_and_clean_messages(raw_messages)
        
        # Step 3: Save clean data to JSON
        print(f"Saving {len(final_messages)} messages to {output_json}...")
        with open(output_json, "w", encoding="utf-8") as json_file:
            json.dump(final_messages, json_file, indent=4, ensure_ascii=False)
            
        print("Done! Export processing complete.")

    except FileNotFoundError:
        print(f"Error: Could not find '{input_html}'. Please check the file path.")
    except Exception as e:
        print(f"An unexpected error occurred: {e}")


if __name__ == "__main__":
    main()
