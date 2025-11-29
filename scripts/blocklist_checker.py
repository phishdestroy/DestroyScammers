import os
import sys
import json
import re
import argparse
import requests
from datetime import datetime
from pathlib import Path
from utils import log

SCRIPT_DIR = Path(__file__).parent
CACHE_DIR = SCRIPT_DIR / 'cache'
CACHE_FILE = CACHE_DIR / 'blocklist_cache.json'
CACHE_MAX_AGE = 3600 * 6

SOURCES_CONFIG = {
    "MetaMask": "https://raw.githubusercontent.com/MetaMask/eth-phishing-detect/master/src/config.json",
    "ScamSniffer": "https://raw.githubusercontent.com/scamsniffer/scam-database/main/blacklist/domains.json",
    "PhishDestroy": "https://raw.githubusercontent.com/phishdestroy/destroylist/main/list.json"
}

def normalize_domain(d: str) -> str:
    return d.strip().lower().split('/')[0]

def fetch_blocklist(url: str) -> set:
    try:
        resp = requests.get(url, timeout=10)
        if resp.status_code == 200:
            if url.endswith('.json'):
                data = resp.json()
                if isinstance(data, list): return {normalize_domain(x) for x in data if isinstance(x, str)}
                if 'blacklist' in data: return {normalize_domain(x) for x in data['blacklist']}
                if 'domains' in data: return {normalize_domain(x) for x in data['domains']}
            return {normalize_domain(line) for line in resp.text.splitlines() if '.' in line}
    except:
        pass
    return set()

def update_cache():
    CACHE_DIR.mkdir(exist_ok=True)
    domains = set()
    for name, url in SOURCES_CONFIG.items():
        domains.update(fetch_blocklist(url))
    
    with open(CACHE_FILE, 'w') as f:
        json.dump({'updated': datetime.now().isoformat(), 'domains': list(domains)}, f)

def check_domain(domain: str) -> bool:
    if not CACHE_FILE.exists():
        update_cache()
    
    with open(CACHE_FILE, 'r') as f:
        data = json.load(f)
        
    return domain in set(data['domains'])

# --- INTEGRATION FUNCTION ---
def scan(domain: str, output_folder: str = None):
    log(f"Checking blocklists for {domain}...", 'info')
    is_blocked = check_domain(domain)
    
    if is_blocked:
        log(f"BLOCKED: {domain} found in blacklist!", 'critical')
    else:
        log(f"Clean (Blocklists): {domain}", 'success')

    if output_folder:
        res = {'domain': domain, 'blocked': is_blocked}
        with open(os.path.join(output_folder, f"{domain}_blocklist.json"), 'w') as f:
            json.dump(res, f, indent=2)

if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('command', choices=['check', 'update'])
    parser.add_argument('domain', nargs='?')
    args = parser.parse_args()
    
    if args.command == 'update':
        update_cache()
        print("Updated.")
    elif args.command == 'check' and args.domain:
        print("Blocked" if check_domain(args.domain) else "Clean")