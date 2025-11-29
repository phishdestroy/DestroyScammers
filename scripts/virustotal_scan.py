import os
import json
import time
import requests
import argparse
from dotenv import load_dotenv
from utils import log

load_dotenv()
API_KEY = os.getenv('VIRUSTOTAL_API_KEY')
BASE_URL = 'https://www.virustotal.com/api/v3'

def get_domain_report(domain: str):
    if not API_KEY: return None
    headers = {'x-apikey': API_KEY}
    try:
        resp = requests.get(f'{BASE_URL}/domains/{domain}', headers=headers, timeout=20)
        return resp.json() if resp.status_code == 200 else None
    except:
        return None

# --- INTEGRATION FUNCTION ---
def scan(domain: str, output_folder: str = None):
    if not API_KEY:
        log("Skipping VirusTotal (No API Key)", 'warning')
        return

    log(f"Querying VirusTotal for {domain}...", 'info')
    report = get_domain_report(domain)
    
    if report:
        stats = report.get('data', {}).get('attributes', {}).get('last_analysis_stats', {})
        malicious = stats.get('malicious', 0)
        
        if malicious > 0:
            log(f"MALICIOUS: {malicious} detections!", 'critical')
        else:
            log("VirusTotal: Clean", 'success')

        if output_folder:
            with open(os.path.join(output_folder, f"{domain}_virustotal.json"), 'w') as f:
                json.dump(report, f, indent=2)
    else:
        log("VirusTotal: No data found or Error", 'warning')

if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('domain')
    args = parser.parse_args()
    print(json.dumps(get_domain_report(args.domain), indent=2))