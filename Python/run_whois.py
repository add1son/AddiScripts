import ipaddress
import argparse
import sys
import time
from ipwhois import IPWhois
from ipwhois.exceptions import IPDefinedError, ASNRegistryError, WhoisLookupError, HTTPLookupError

# --- Configuration ---
# Delay between WHOIS queries to avoid rate limiting (in seconds)
QUERY_DELAY = 1.0

# --- Helper Functions ---

def read_ips_from_file(filename):
    """Reads IPs from a file, expecting one IP per line."""
    ips = []
    print(f"Reading input IPs from {filename}...")
    try:
        with open(filename, 'r') as f:
            lines = f.readlines()
            count = 0
            invalid_count = 0
            for i, line in enumerate(lines, 1):
                ip_str = line.strip()
                if not ip_str or ip_str.startswith('#'):
                    continue # Skip empty lines/comments

                try:
                    # Validate IP format
                    ipaddress.ip_address(ip_str)
                    ips.append(ip_str)
                    count += 1
                except ValueError:
                    print(f"  [Warning] Invalid IP address format in {filename} on line {i}: '{ip_str}'", file=sys.stderr)
                    invalid_count += 1

            print(f"  Read {count} valid IPs ({invalid_count} invalid entries skipped).")
            if not ips:
                 print("[Error] No valid IPs found in input file.", file=sys.stderr)
                 sys.exit(1)
            return ips
    except FileNotFoundError:
        print(f"[Error] Input file not found: {filename}", file=sys.stderr)
        sys.exit(1)
    except Exception as e:
        print(f"[Error] Failed to read input file {filename}: {e}", file=sys.stderr)
        sys.exit(1)

def get_whois_info(ip_address):
    """Performs RDAP/WHOIS lookup and extracts key info."""
    print(f"\n--- Querying WHOIS/RDAP for: {ip_address} ---")
    try:
        obj = IPWhois(ip_address)
        # Use legacy whois; it can sometimes provide more descriptive network names
        # Removed the invalid 'quiet=True' argument here:
        results = obj.lookup_whois(inc_raw=False, retry_count=2)

        if not results:
            print("  [Info] No WHOIS results returned.")
            return None

        # Extract relevant information
        asn = results.get('asn', 'N/A')
        asn_desc = results.get('asn_description', 'N/A')
        net_name = 'N/A'
        org_name = 'N/A' # Hard to reliably get consistent Org name from legacy WHOIS directly
        net_desc = 'N/A'

        if results.get('nets') and isinstance(results['nets'], list) and len(results['nets']) > 0:
            network_info = results['nets'][0]
            net_name = network_info.get('name', 'N/A')
            net_desc = network_info.get('description', 'N/A') # Often contains useful info

        print(f"  ASN:         {asn}")
        print(f"  ASN Desc:    {asn_desc}")
        print(f"  Network Name:{net_name}")
        print(f"  Network Desc:{net_desc if net_desc else 'N/A'}")

        # --- Heuristic Analysis (Use with caution!) ---
        combined_info = f"{asn_desc} {net_name} {net_desc}".lower()
        residential_keywords = ["isp", "broadband", "cable", "telecom", "fios", "dsl", "residential", "internet services", "comcast", "verizon", "at&t", "cox", "charter", "spectrum"]
        non_res_keywords = ["hosting", "cloud", "server", "data center", "datacenter", "vps", "vpn", "proxy", "colocation", "cdn", "aws", "google", "azure", "digitalocean", "ovh", "linode"]

        is_likely_res = any(keyword in combined_info for keyword in residential_keywords)
        is_likely_non_res = any(keyword in combined_info for keyword in non_res_keywords)

        if is_likely_res and not is_likely_non_res:
            print("  Assessment:  [Potentially Residential ISP based on keywords]")
        elif is_likely_non_res:
            print("  Assessment:  [Potentially Non-Residential (Hosting/DC/VPN) based on keywords]")
        else:
            print("  Assessment:  [Undetermined / Needs Manual Review]")
        # --- End Heuristic Analysis ---

        return results # Return full results if needed later

    except (IPDefinedError, ValueError) as e:
        print(f"  [Info] Skipping private, reserved, or invalid IP: {ip_address} ({e})")
        return None
    except (ASNRegistryError, WhoisLookupError, HTTPLookupError) as e:
        print(f"  [Error] WHOIS/RDAP lookup failed for {ip_address}: {e}", file=sys.stderr)
        return None
    except Exception as e:
        print(f"  [Error] An unexpected error occurred during lookup for {ip_address}: {e}", file=sys.stderr)
        return None

# --- Main Execution ---
def main():
    parser = argparse.ArgumentParser(description="Perform WHOIS lookups on a list of IPs to assess if they belong to residential ISPs.")
    parser.add_argument("-i", "--input", required=True, help="Path to the input file containing IPs (one per line).")
    args = parser.parse_args()

    ips_to_check = read_ips_from_file(args.input)
    total_ips = len(ips_to_check)
    print(f"\nStarting WHOIS lookups for {total_ips} IPs...")

    results_summary = []

    for i, ip in enumerate(ips_to_check):
        info = get_whois_info(ip)
        # if info: # Optional: store info if needed later
        #     results_summary.append(...)

        print(f"  Processed {i + 1} of {total_ips} IPs.")

        if i < total_ips - 1:
             print(f"  Waiting {QUERY_DELAY}s before next query...")
             time.sleep(QUERY_DELAY)

    print("\nWHOIS lookups complete.")
    # Optional: Add code here to write results_summary to a CSV or JSON file

if __name__ == "__main__":
    main()