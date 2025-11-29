import os
import sys
from pathlib import Path
from dotenv import load_dotenv

import utils
import crtsh_lookup
import dns_lookup
import blocklist_checker
import urlscan_search
import virustotal_scan

load_dotenv()

BASE_DIR = Path(__file__).parent
INPUT_FILE = BASE_DIR / 'domains.txt'
OUTPUT_DIR = BASE_DIR / 'output'

def setup():
    if not OUTPUT_DIR.exists():
        OUTPUT_DIR.mkdir()
    
    if not INPUT_FILE.exists():
        with open(INPUT_FILE, 'w') as f:
            f.write("google.com\nexample.com")
        utils.log("File 'domains.txt' created. Add targets there.", 'warning')
        sys.exit()

def read_domains():
    with open(INPUT_FILE, 'r') as f:
        return [line.strip() for line in f if line.strip()]

def main():
    utils.banner()
    setup()
    
    domains = read_domains()
    utils.log(f"Loaded {len(domains)} targets.", 'info')
    
    for domain in domains:
        utils.log(f"ANALYZING: {domain}", 'critical')
        
        # 1. Blocklist Check (No Key)
        try:
            blocklist_checker.scan(domain, str(OUTPUT_DIR))
        except Exception as e:
            utils.log(f"Blocklist error: {e}", 'error')

        # 2. DNS Analysis (No Key)
        try:
            dns_lookup.scan(domain, str(OUTPUT_DIR))
        except Exception as e:
            utils.log(f"DNS error: {e}", 'error')

        # 3. Subdomain Search (No Key)
        try:
            crtsh_lookup.scan(domain, str(OUTPUT_DIR))
        except Exception as e:
            utils.log(f"CRT.sh error: {e}", 'error')

        # 4. VirusTotal (Requires Key)
        try:
            virustotal_scan.scan(domain, str(OUTPUT_DIR))
        except Exception as e:
            utils.log(f"VirusTotal error: {e}", 'error')

        # 5. URLScan.io (Requires Key)
        try:
            urlscan_search.scan(domain, str(OUTPUT_DIR))
        except Exception as e:
            utils.log(f"URLScan error: {e}", 'error')

        print("-" * 50)

    utils.log("All scans completed. Check 'output' folder.", 'success')

if __name__ == "__main__":
    main()