# Python Scripts

Welcome to the Python folder! This directory contains a collection of Python scripts designed to automate tasks and perform various functions.

## Scripts

### [word_count.py](https://github.com/add1son/AddiScripts/blob/main/Python/word_count.py)
- **Description:** Counts a total number of words for a markdown file, 
- **Functionality:** I use this for a folder of markdown files for use with [obsidian.md](https://obsidian.md/)

### [run_whois.py](https://github.com/add1son/AddiScripts/blob/main/Python/run_whois.py)
- **Description:** Performs mass WHOIS/RDAP lookups on a list of IP addresses and uses keyword heuristics to analyze network data.
- **Functionality:** I use this to process a raw list of target IPs and identify whether they are likely residential ISPs, cloud data centers, or hosting providers.

### [filter_ips_tor_vpn.py](https://github.com/add1son/AddiScripts/blob/main/Python/filter_ips_tor_vpn.py)
- **Description:** Cross-references a list of IP addresses against live Tor exit nodes, custom CIDR blocks, and local exclusion lists.
- **Functionality:** I use this to automatically filter out known VPNs, data centers, proxies, and Tor nodes to isolate organic or residential traffic.

### [combine_notes.py](https://github.com/add1son/AddiScripts/blob/main/Python/combine_notes.py)
- **Description:** Combines multiple individual Markdown files from a specified folder into a single, organized master document.
- **Functionality:** I use this for a folder of markdown files for use with obsidian.md to merge daily notes, logs, or archives for easier backup and LLM ingestion.

### [TG_Archive_Html_to_json.py](https://github.com/add1son/AddiScripts/blob/main/Python/TG_Archive_Html_to_json.py)
- **Description:** A lightweight Python script that parses, cleans, and structures Telegram chat histories exported in HTML format into a normalized JSON dataset. It automatically resolves common export artifacts, such as empty system notifications and missing sender names on sequential messages.
- **Functionality:**
    - **HTML Parsing:** Uses `BeautifulSoup` to safely extract sender names, message text, and timestamps from native Telegram HTML structures.
    - **In-Memory Efficiency:** Processes parsing, data sanitization, and transformations entirely in memory to eliminate redundant file I/O.
    - **Name Forward-Filling:** Fixes Telegram's layout behavior by automatically propagating the sender's name downward to consecutive messages.
    - **Data Sanitization:** Drops empty records and system logs missing both text and sender details during the initial extraction pass.
    - **Clean JSON Export:** Generates a properly indented, UTF-8 encoded JSON file (`messages_cleaned.json`) that fully preserves emojis and non-ASCII text.
    - **Error Handling:** Features basic exception handling to catch missing input files gracefully without throwing raw stack traces.

### [sort_media.py](https://github.com/add1son/AddiScripts/blob/main/Python/sort_media.py)
- **Description:** Sort data into folders based on file metadata
- **Functionality:**
    - **Immich:** sorts a folder into folders based on date the media was taken 

## Usage

1. Clone or download the contents of this repository to your local machine.
2. Navigate to the Python folder.
3. Open any script file (*.py) in a text editor or an integrated development environment (IDE) such as PyCharm, VSCode, or IDLE.
4. Review the script comments for any additional instructions, usage examples, or configuration settings.
5. Save the changes to the script file if any modifications are made.
6. Run the script using Python interpreter by executing `python ScriptName.py` in the terminal or command prompt.

## Additional Resources
* [Awesome-Python-Scripts](https://github.com/hastagAB/Awesome-Python-Scripts)
* [awesome python](https://github.com/vinta/awesome-python)
