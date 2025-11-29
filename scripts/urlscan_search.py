import os
import json
import time
import argparse
import requests
from dotenv import load_dotenv
from utils import log

load_dotenv()
API_KEY = os.getenv('URLSCAN_API_KEY')
BASE_URL = 'https://urlscan.io/api/v1'

def search_domain(domain: str) -> list:
    try:
        resp = requests.get(f'{BASE_URL}/search/', params={'q': f'domain:{domain}', 'size': 5}, timeout=20)
        return resp.json().get('results', []) if resp.status_code == 200 else []
    except:
        return []

def submit_scan(domain: str):
    if not API_KEY: return None
    headers = {'API-Key': API_KEY, 'Content-Type': 'application/json'}
    try:
        resp = requests.post(f'{BASE_URL}/scan/', headers=headers, json={'url': domain, 'visibility': 'public'}, timeout=20)
        return resp.json() if resp.status_code == 200 else None
    except:
        return None

def get_result(uuid: str):
    try:
        resp = requests.get(f'{BASE_URL}/result/{uuid}/', timeout=20)
        return resp.json() if resp.status_code == 200 else None
    except:
        return None

# --- INTEGRATION FUNCTION ---
def scan(domain: str, output_folder: str = None):
    if not API_KEY:
        log("Skipping URLScan (No API Key)", 'warning')
        return

    log(f"Searching URLScan.io for {domain}...", 'info')
    results = search_domain(domain)
    
    if results:
        log(f"Found {len(results)} existing scans.", 'success')
        data = results
    else:
        log("No existing scans. Submitting new scan...", 'warning')
        scan_info = submit_scan(domain)
        if scan_info:
            time.sleep(15)
            res = get_result(scan_info['uuid'])
            data = [res] if res else []
        else:
            data = []

    if output_folder and data:
        with open(os.path.join(output_folder, f"{domain}_urlscan.json"), 'w') as f:
            json.dump(data, f, indent=2)

if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('domain')
    args = parser.parse_args()
    print(search_domain(args.domain))