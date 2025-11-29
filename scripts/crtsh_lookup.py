import requests
import json
import argparse
import os
from utils import log

def get_subdomains(domain: str) -> list:
    url = f"https://crt.sh/?q=%.{domain}&output=json"
    headers = {'User-Agent': 'Mozilla/5.0 (compatible; OSINTTool/1.0)'}
    
    try:
        resp = requests.get(url, headers=headers, timeout=20)
        if resp.status_code != 200:
            return []
            
        data = resp.json()
        subdomains = set()
        
        for entry in data:
            name_value = entry.get('name_value', '')
            for sub in name_value.split('\n'):
                if '*' not in sub and sub.strip():
                    subdomains.add(sub.strip().lower())
                    
        return sorted(list(subdomains))
    except Exception:
        return []

def scan(domain: str, output_folder: str = None):
    log(f"Running CRT.sh subdomain search for {domain}...", 'info')
    results = get_subdomains(domain)

    if results:
        log(f"Found {len(results)} subdomains.", 'success')
        
        if output_folder:
            filename = os.path.join(output_folder, f"{domain}_subdomains.json")
            with open(filename, 'w') as f:
                json.dump(results, f, indent=2)
    else:
        log("No subdomains found.", 'warning')

if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('domain')
    parser.add_argument('--output', '-o')
    args = parser.parse_args()
    
    subs = get_subdomains(args.domain)
    print(json.dumps(subs, indent=2))