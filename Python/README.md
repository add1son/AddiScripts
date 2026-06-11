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
