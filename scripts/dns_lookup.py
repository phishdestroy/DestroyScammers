import argparse
import dns.resolver
import json
import os
from utils import log

def get_records(domain: str, record_type: str) -> list:
    try:
        answers = dns.resolver.resolve(domain, record_type)
        return [r.to_text().strip('"') for r in answers]
    except:
        return []

def scan(domain: str, output_folder: str = None):
    log(f"Running DNS analysis for {domain}...", 'info')
    
    data = {
        'A': get_records(domain, 'A'),
        'MX': get_records(domain, 'MX'),
        'TXT': get_records(domain, 'TXT'),
        'NS': get_records(domain, 'NS')
    }

    if any(data.values()):
        log(f"DNS records found.", 'success')
        if output_folder:
            filename = os.path.join(output_folder, f"{domain}_dns.json")
            with open(filename, 'w') as f:
                json.dump(data, f, indent=2)
    else:
        log("No DNS records found.", 'warning')

if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('domain')
    args = parser.parse_args()
    
    print(f"A: {get_records(args.domain, 'A')}")