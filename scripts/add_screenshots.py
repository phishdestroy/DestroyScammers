#!/usr/bin/env python3
"""
Add Screenshots Script - Finds domains without screenshots and adds them from URLScan
Updates data.json directly for easy GitHub sync

Usage: python add_screenshots.py [--limit N] [--dry-run]
"""

import json
import os
import sys
import time
import requests
from datetime import datetime
from pathlib import Path
import logging

# Setup logging
LOG_FILE = Path(__file__).parent / 'screenshots.log'
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] %(message)s',
    handlers=[
        logging.FileHandler(LOG_FILE, encoding='utf-8'),
        logging.StreamHandler(sys.stdout)
    ]
)
log = logging.getLogger(__name__)

# Configuration
DATA_FILE = Path(__file__).parent.parent / 'data' / 'data.json'
URLSCAN_SEARCH_URL = 'https://urlscan.io/api/v1/search/'
URLSCAN_RESULT_URL = 'https://urlscan.io/api/v1/result/'
URLSCAN_SUBMIT_URL = 'https://urlscan.io/api/v1/scan/'

# Load API keys from environment
_env_keys = os.environ.get('URLSCAN_API_KEYS', os.environ.get('URLSCAN_API_KEY', ''))
API_KEYS = [k.strip() for k in _env_keys.split(',') if k.strip()]

# Rate limiting
key_index = 0
requests_made = 0
start_time = time.time()

def get_api_key():
    """Get next API key for rotation"""
    global key_index
    if not API_KEYS:
        return None
    key = API_KEYS[key_index % len(API_KEYS)]
    key_index += 1
    return key

def rate_limit():
    """Simple rate limiting - max 2 requests per second"""
    global requests_made, start_time
    requests_made += 1
    elapsed = time.time() - start_time
    if elapsed < 0.5:
        time.sleep(0.5 - elapsed)
    start_time = time.time()

def search_urlscan(domain: str) -> dict | None:
    """Search URLScan for existing scan of domain"""
    rate_limit()
    try:
        url = f'{URLSCAN_SEARCH_URL}?q=domain:{domain}&size=1'
        response = requests.get(url, timeout=15)
        if response.status_code == 200:
            data = response.json()
            results = data.get('results', [])
            if results:
                scan = results[0]
                uuid = scan.get('_id')
                screenshot = scan.get('screenshot')
                if screenshot:
                    return {
                        'uuid': uuid,
                        'screenshot': screenshot,
                        'found': True
                    }
                # Try to get full result for more data
                if uuid:
                    return get_scan_result(uuid)
        elif response.status_code == 429:
            log.warning(f"Rate limited on search, waiting 60s...")
            time.sleep(60)
            return search_urlscan(domain)
    except Exception as e:
        log.debug(f"Search error for {domain}: {e}")
    return None

def get_scan_result(uuid: str) -> dict | None:
    """Get full scan result by UUID"""
    rate_limit()
    try:
        url = f'{URLSCAN_RESULT_URL}{uuid}/'
        response = requests.get(url, timeout=15)
        if response.status_code == 200:
            result = response.json()
            screenshot = result.get('task', {}).get('screenshotURL') or f"https://urlscan.io/screenshots/{uuid}.png"
            return {
                'uuid': uuid,
                'screenshot': screenshot,
                'ip': result.get('page', {}).get('ip', ''),
                'country': result.get('page', {}).get('country', ''),
                'title': result.get('page', {}).get('title', ''),
                'malicious': result.get('verdicts', {}).get('overall', {}).get('malicious', False),
                'found': True
            }
    except Exception as e:
        log.debug(f"Result error for {uuid}: {e}")
    return None

def submit_scan(domain: str) -> dict | None:
    """Submit new scan to URLScan (requires API key)"""
    api_key = get_api_key()
    if not api_key:
        log.warning("No API key available for submitting new scans")
        return None

    rate_limit()
    try:
        headers = {
            'API-Key': api_key,
            'Content-Type': 'application/json'
        }
        data = {
            'url': f'https://{domain}',
            'visibility': 'public'
        }
        response = requests.post(URLSCAN_SUBMIT_URL, headers=headers, json=data, timeout=15)
        if response.status_code == 200:
            result = response.json()
            uuid = result.get('uuid')
            log.info(f"  Submitted scan for {domain}, waiting for result...")
            time.sleep(15)  # Wait for scan to complete
            return get_scan_result(uuid)
        elif response.status_code == 429:
            log.warning(f"Rate limited on submit, waiting 60s...")
            time.sleep(60)
            return submit_scan(domain)
        elif response.status_code == 400:
            log.debug(f"Cannot scan {domain}: {response.text}")
    except Exception as e:
        log.debug(f"Submit error for {domain}: {e}")
    return None

def find_domains_without_screenshots(data: dict) -> list:
    """Find all domains that don't have screenshots yet"""
    domains_without = []

    for person in data.get('emails', []):
        email = person.get('email', 'unknown')
        urlscan_data = person.get('urlscan', {})
        domain_cards = {c.get('domain'): c for c in person.get('domain_cards', [])}

        for domain in person.get('domains', []):
            # Check if already has screenshot in urlscan
            us = urlscan_data.get(domain, {})
            if us.get('found') and us.get('screenshot'):
                continue

            # Check if already has screenshot in domain_cards
            card = domain_cards.get(domain, {})
            if card.get('screenshot'):
                continue

            domains_without.append({
                'domain': domain,
                'email': email,
                'person_index': data['emails'].index(person)
            })

    return domains_without

def update_data_with_screenshot(data: dict, domain_info: dict, scan_result: dict):
    """Update data.json with new screenshot info"""
    person = data['emails'][domain_info['person_index']]
    domain = domain_info['domain']

    # Update urlscan section
    if 'urlscan' not in person:
        person['urlscan'] = {}

    person['urlscan'][domain] = {
        'found': True,
        'scan_id': scan_result.get('uuid', ''),
        'screenshot': scan_result.get('screenshot', ''),
        'ip': scan_result.get('ip', ''),
        'country': scan_result.get('country', ''),
        'title': scan_result.get('title', ''),
        'malicious': scan_result.get('malicious', False),
        'scanned_at': datetime.now().isoformat()
    }

    # Update domain_cards
    if 'domain_cards' not in person:
        person['domain_cards'] = []

    # Find or create card
    card_found = False
    for card in person['domain_cards']:
        if card.get('domain') == domain:
            card['screenshot'] = scan_result.get('screenshot', '')
            card['ip'] = scan_result.get('ip', '')
            card['country'] = scan_result.get('country', '')
            card_found = True
            break

    if not card_found:
        person['domain_cards'].append({
            'domain': domain,
            'screenshot': scan_result.get('screenshot', ''),
            'ip': scan_result.get('ip', ''),
            'country': scan_result.get('country', '')
        })

def main():
    # Parse arguments
    limit = None
    dry_run = False
    submit_new = False

    for i, arg in enumerate(sys.argv[1:], 1):
        if arg == '--limit' and i < len(sys.argv) - 1:
            limit = int(sys.argv[i + 1])
        elif arg == '--dry-run':
            dry_run = True
        elif arg == '--submit':
            submit_new = True

    log.info("=" * 60)
    log.info("Add Screenshots Script Started")
    log.info("=" * 60)

    # Check API keys
    if API_KEYS:
        log.info(f"API keys loaded: {len(API_KEYS)}")
    else:
        log.warning("No API keys configured - will only search existing scans")
        log.info("Set URLSCAN_API_KEYS environment variable for new scans")

    # Load data
    if not DATA_FILE.exists():
        log.error(f"Data file not found: {DATA_FILE}")
        return 1

    log.info(f"Loading data from {DATA_FILE}")
    with open(DATA_FILE, 'r', encoding='utf-8') as f:
        data = json.load(f)

    # Find domains without screenshots
    domains_without = find_domains_without_screenshots(data)
    log.info(f"Found {len(domains_without)} domains without screenshots")

    if limit:
        domains_without = domains_without[:limit]
        log.info(f"Limited to {limit} domains")

    if dry_run:
        log.info("DRY RUN - not making any changes")
        for d in domains_without[:20]:
            log.info(f"  Would check: {d['domain']} ({d['email']})")
        if len(domains_without) > 20:
            log.info(f"  ... and {len(domains_without) - 20} more")
        return 0

    # Process domains
    found_count = 0
    not_found_count = 0
    error_count = 0

    for i, domain_info in enumerate(domains_without):
        domain = domain_info['domain']
        progress = f"[{i+1}/{len(domains_without)}]"

        try:
            # First search for existing scan
            result = search_urlscan(domain)

            # If not found and submit enabled, try to submit new scan
            if not result and submit_new and API_KEYS:
                result = submit_scan(domain)

            if result and result.get('screenshot'):
                log.info(f"{progress} FOUND: {domain}")
                update_data_with_screenshot(data, domain_info, result)
                found_count += 1

                # Save periodically (every 10 found)
                if found_count % 10 == 0:
                    log.info(f"Saving progress ({found_count} screenshots added)...")
                    with open(DATA_FILE, 'w', encoding='utf-8') as f:
                        json.dump(data, f, ensure_ascii=False)
            else:
                log.debug(f"{progress} Not found: {domain}")
                not_found_count += 1

        except KeyboardInterrupt:
            log.warning("Interrupted by user, saving progress...")
            break
        except Exception as e:
            log.error(f"{progress} Error processing {domain}: {e}")
            error_count += 1

    # Final save
    log.info("Saving final data...")
    with open(DATA_FILE, 'w', encoding='utf-8') as f:
        json.dump(data, f, ensure_ascii=False)

    # Summary
    log.info("=" * 60)
    log.info("SUMMARY")
    log.info("=" * 60)
    log.info(f"Domains processed: {len(domains_without)}")
    log.info(f"Screenshots found: {found_count}")
    log.info(f"Not found: {not_found_count}")
    log.info(f"Errors: {error_count}")
    log.info(f"Data saved to: {DATA_FILE}")
    log.info("=" * 60)

    return 0

if __name__ == '__main__':
    sys.exit(main())
