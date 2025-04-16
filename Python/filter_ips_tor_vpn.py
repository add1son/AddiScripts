import ipaddress
import requests
import argparse
import sys
from datetime import datetime

# --- Configuration ---

# URL for the official Tor exit node list
TOR_EXIT_LIST_URL = "https://check.torproject.org/torbulkexitlist"

# Add known CIDR blocks to exclude here (e.g., hosting providers)
# Example: '192.0.2.0/24', '203.0.113.0/24'
# These can also be added via --exclude-cidr argument or the local file
CUSTOM_EXCLUDE_CIDRS = [
    # '1.2.3.0/24',
]

# --- Local Exclusion File ---
# Name of the local file containing known VPN/Data Center IPs and/or CIDRs (one per line)
# Place this file in the same directory as the script.
LOCAL_EXCLUSION_FILE = "knownvpn_datacenter.txt"

# --- Helper Functions ---

def fetch_ip_list_from_url(url, description):
    """Fetches a list of IPs from a URL, expecting one IP per line."""
    print(f"Fetching {description} from {url}...")
    ips = set()
    try:
        headers = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/100.0.0.0 Safari/537.36'}
        response = requests.get(url, timeout=30, headers=headers)
        response.raise_for_status()

        lines = response.text.splitlines()
        count = 0
        for line in lines:
            line = line.strip()
            if line and not line.startswith('#'):
                try:
                    ipaddress.ip_address(line) # Validate format only
                    ips.add(line)
                    count += 1
                except ValueError:
                    # print(f"  [Warning] Ignoring invalid IP entry in {description}: {line}")
                    pass
        print(f"  Fetched {count} valid IPs from {description}.")
        return ips

    except requests.exceptions.RequestException as e:
        print(f"  [Error] Failed to fetch {description} from {url}: {e}", file=sys.stderr)
        return set()

def read_ips_from_file(filename, description):
    """Reads IPs from a local file, expecting one IP per line (strips whitespace)."""
    ips = set()
    print(f"Reading {description} from {filename}...")
    try:
        with open(filename, 'r') as f:
            lines = f.readlines()
            count = 0
            invalid_count = 0
            for i, line in enumerate(lines, 1):
                ip_str = line.strip()
                if not ip_str or ip_str.startswith('#'):
                    continue

                try:
                    ip_obj = ipaddress.ip_address(ip_str)
                    ips.add(ip_obj)
                    count += 1
                except ValueError:
                    print(f"  [Warning] Invalid IP address format in {filename} on line {i}: '{ip_str}'", file=sys.stderr)
                    invalid_count += 1

            print(f"  Read {count} valid IPs ({invalid_count} invalid entries skipped) from {description}.")
            return ips
    except FileNotFoundError:
        print(f"[Error] {description} file not found: {filename}", file=sys.stderr)
        return set()
    except Exception as e:
        print(f"[Error] Failed to read {description} file {filename}: {e}", file=sys.stderr)
        return set()

# --- Main Execution ---

def main():
    parser = argparse.ArgumentParser(description="Filter a list of IP addresses against Tor exit nodes, custom CIDRs, and a local IP/CIDR exclusion file.")
    parser.add_argument("-i", "--input", required=True, help="Path to the input file (one IP per line).")
    parser.add_argument("-o", "--output", required=True, help="Path to the output file for filtered (potentially residential) IPs.")
    parser.add_argument("--exclude-cidr", action='append', default=[], help="Add a CIDR block to the exclusion list (e.g., 192.0.2.0/24). Can be used multiple times.")
    parser.add_argument("--local-exclude-file", default=LOCAL_EXCLUSION_FILE, help=f"Path to a local file containing IPs and/or CIDRs to exclude (default: {LOCAL_EXCLUSION_FILE}).")
    args = parser.parse_args()

    # Use the provided filename for local exclusions
    local_exclude_filename = args.local_exclude_file

    print(f"Script started at: {datetime.now()}")
    print(f"Using local exclusion file: {local_exclude_filename}")

    # --- 1. Gather Exclusion Data ---
    exclusion_networks = set() # Stores ipaddress.ip_network objects
    exclusion_ip_strings = set() # Stores string representations of individual IPs initially

    # Add custom CIDRs from config and command line arguments
    all_custom_cidrs_args = CUSTOM_EXCLUDE_CIDRS + args.exclude_cidr
    print("\nProcessing exclusion CIDRs from config/arguments...")
    for cidr_str in all_custom_cidrs_args:
        cidr_str = cidr_str.strip()
        if not cidr_str or cidr_str.startswith('#'):
            continue
        try:
            network = ipaddress.ip_network(cidr_str, strict=False)
            exclusion_networks.add(network)
            print(f"  Added exclusion CIDR: {cidr_str}")
        except ValueError:
            print(f"  [Warning] Invalid CIDR format skipped from config/args: '{cidr_str}'", file=sys.stderr)

    # Fetch Tor Exit Nodes
    tor_ips = fetch_ip_list_from_url(TOR_EXIT_LIST_URL, "Tor Exit Nodes")
    exclusion_ip_strings.update(tor_ips) # Add individual Tor IPs (as strings)

    # --- Read IPs/CIDRs from Local Exclusion File ---
    # ***** MODIFIED SECTION *****
    print(f"\nReading local exclusion IPs/CIDRs from {local_exclude_filename}...")
    local_exclude_ip_count = 0
    local_exclude_cidr_count = 0
    local_invalid_count = 0
    try:
        with open(local_exclude_filename, 'r') as f:
            for i, line in enumerate(f, 1):
                entry_str = line.strip()
                if not entry_str or entry_str.startswith('#'): # Skip empty/comment lines
                    continue

                try:
                    # Attempt 1: Parse as individual IP address
                    ip_obj = ipaddress.ip_address(entry_str)
                    # If successful, it's an individual IP
                    exclusion_ip_strings.add(str(ip_obj)) # Add its string representation
                    local_exclude_ip_count += 1
                except ValueError:
                    # Attempt 2: If not an IP, try parsing as CIDR network
                    try:
                        network_obj = ipaddress.ip_network(entry_str, strict=False)
                        # If successful, it's a CIDR network
                        exclusion_networks.add(network_obj) # Add the network object
                        local_exclude_cidr_count += 1
                    except ValueError:
                        # Attempt 3: If neither works, it's an invalid format
                        print(f"  [Warning] Invalid IP/CIDR format in {local_exclude_filename} on line {i}: '{entry_str}'", file=sys.stderr)
                        local_invalid_count += 1

        print(f"  Read {local_exclude_ip_count} valid IPs and {local_exclude_cidr_count} valid CIDRs ({local_invalid_count} invalid entries skipped) from {local_exclude_filename}.")

    except FileNotFoundError:
        print(f"  [Warning] Local exclusion file not found: {local_exclude_filename}. Skipping.", file=sys.stderr)
    except Exception as e:
        print(f"  [Error] Failed to read local exclusion file {local_exclude_filename}: {e}", file=sys.stderr)
        # Depending on severity, consider sys.exit(1)

    # --- Consolidate and Finalize Exclusion Data ---
    print(f"\nTotal exclusion networks (CIDRs): {len(exclusion_networks)}")
    print(f"Total individual exclusion IPs (Tor, Local File): {len(exclusion_ip_strings)}")

    # Convert individual exclusion IP strings to ipaddress objects for efficient comparison
    exclusion_ip_objects = set()
    conversion_errors = 0
    for ip_str in exclusion_ip_strings:
        try:
            exclusion_ip_objects.add(ipaddress.ip_address(ip_str))
        except ValueError:
             print(f"  [Warning] Skipping invalid IP during final conversion: {ip_str}", file=sys.stderr)
             conversion_errors += 1
    if conversion_errors > 0:
         print(f"  [Warning] {conversion_errors} IPs skipped during final conversion.")

    # --- 2. Load Input IPs ---
    input_ips = read_ips_from_file(args.input, "Input IPs")
    if not input_ips:
        print("[Error] No valid IPs found in the input file. Exiting.", file=sys.stderr)
        sys.exit(1)

    # --- 3. Filter IPs ---
    print("\nFiltering IPs...")
    potentially_residential_ips = []
    excluded_count = 0

    for ip_obj in input_ips: # These are already ipaddress objects
        excluded = False
        reason = ""

        # Check 1: Against individual exclusion IPs
        if ip_obj in exclusion_ip_objects:
            excluded = True
            reason = "Listed IP (Tor/Local File)"
        else:
            # Check 2: Against exclusion CIDR blocks
            for network in exclusion_networks:
                if ip_obj in network:
                    excluded = True
                    reason = f"CIDR Match ({network})"
                    break # Found in a network, no need to check others

        if not excluded:
            potentially_residential_ips.append(ip_obj)
        else:
            excluded_count += 1
            # print(f"  Excluding {ip_obj} ({reason})") # Uncomment for detailed exclusion logs

    print(f"  Filtering complete. {excluded_count} IPs were excluded.")
    print(f"  {len(potentially_residential_ips)} IPs remain (potentially residential).")

    # --- 4. Write Output ---
    print(f"\nWriting remaining IPs to {args.output}...")
    try:
        with open(args.output, 'w') as f:
            for ip_obj in sorted(potentially_residential_ips, key=ipaddress.get_mixed_type_key):
                f.write(f"{str(ip_obj)}\n")
        print(f"  Successfully wrote {len(potentially_residential_ips)} IPs.")
    except Exception as e:
        print(f"[Error] Failed to write output file {args.output}: {e}", file=sys.stderr)
        sys.exit(1)

    # Display current date and time at the end
    print(f"\nScript finished at: {datetime.now().strftime('%Y-%m-%d %H:%M:%S %Z')}") # Added formatting

if __name__ == "__main__":
    main()