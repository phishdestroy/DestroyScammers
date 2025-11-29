#!/usr/bin/env python3
"""
Whoxy.com WHOIS & Reverse WHOIS Lookup Tool
============================================
Query domain registration data and find domains by email/name

Features:
- Domain WHOIS lookup
- Reverse WHOIS by email
- Reverse WHOIS by registrant name
- Reverse WHOIS by company
- Bulk email lookup
- Export to JSON/CSV

Usage:
    python whoxy_lookup.py whois <domain>
    python whoxy_lookup.py email <email@example.com>
    python whoxy_lookup.py name "John Doe"
    python whoxy_lookup.py company "Example Corp"
    python whoxy_lookup.py bulk-email <emails.txt> --output results.json
"""

import os
import sys
import json
import csv
import argparse
import requests
from datetime import datetime
from pathlib import Path
from dotenv import load_dotenv

# Load environment variables
SCRIPT_DIR = Path(__file__).parent
load_dotenv(SCRIPT_DIR / '.env')

API_KEY = os.getenv('WHOXY_API_KEY', '')
BASE_URL = 'https://api.whoxy.com'

def log(msg: str, level: str = 'info') -> None:
    """Print colored log message"""
    colors = {
        'info': '\033[94m[*]\033[0m',
        'success': '\033[92m[+]\033[0m',
        'warning': '\033[93m[!]\033[0m',
        'error': '\033[91m[-]\033[0m'
    }
    print(f"{colors.get(level, '[*]')} {msg}")

def check_api_key():
    """Verify API key is set"""
    if not API_KEY:
        log("No WHOXY_API_KEY set!", 'error')
        log("Get your API key at: https://www.whoxy.com/", 'info')
        log("Add it to scripts/.env file", 'info')
        sys.exit(1)

def whois_lookup(domain: str) -> dict | None:
    """Get WHOIS data for a domain"""
    check_api_key()

    params = {
        'key': API_KEY,
        'whois': domain
    }

    try:
        response = requests.get(BASE_URL, params=params, timeout=30)
        if response.status_code == 200:
            data = response.json()
            if data.get('status') == 1:
                return data
            else:
                log(f"WHOIS lookup failed: {data.get('status_reason', 'Unknown error')}", 'error')
                return None
        else:
            log(f"API error: {response.status_code}", 'error')
            return None
    except Exception as e:
        log(f"Request error: {e}", 'error')
        return None

def reverse_whois(search_type: str, query: str, page: int = 1) -> dict | None:
    """
    Reverse WHOIS lookup
    search_type: 'email', 'name', 'company'
    """
    check_api_key()

    params = {
        'key': API_KEY,
        'reverse': 'whois',
        search_type: query,
        'page': page
    }

    try:
        response = requests.get(BASE_URL, params=params, timeout=30)
        if response.status_code == 200:
            data = response.json()
            if data.get('status') == 1:
                return data
            else:
                log(f"Reverse WHOIS failed: {data.get('status_reason', 'Unknown error')}", 'error')
                return None
        else:
            log(f"API error: {response.status_code}", 'error')
            return None
    except Exception as e:
        log(f"Request error: {e}", 'error')
        return None

def get_all_domains_by_email(email: str) -> list:
    """Get all domains registered by an email (handles pagination)"""
    all_domains = []
    page = 1

    while True:
        log(f"Fetching page {page}...", 'info')
        data = reverse_whois('email', email, page)

        if not data:
            break

        domains = data.get('search_result', [])
        if not domains:
            break

        all_domains.extend(domains)

        total = data.get('total_results', 0)
        fetched = len(all_domains)
        log(f"Fetched {fetched}/{total} domains", 'info')

        if fetched >= total:
            break

        page += 1

    return all_domains

def format_whois_result(data: dict) -> dict:
    """Format WHOIS data for display"""
    return {
        'domain': data.get('domain_name'),
        'registrar': data.get('domain_registrar', {}).get('registrar_name'),
        'created': data.get('create_date'),
        'updated': data.get('update_date'),
        'expires': data.get('expiry_date'),
        'nameservers': data.get('name_servers', []),
        'registrant': {
            'name': data.get('registrant_contact', {}).get('full_name'),
            'company': data.get('registrant_contact', {}).get('company_name'),
            'email': data.get('registrant_contact', {}).get('email_address'),
            'country': data.get('registrant_contact', {}).get('country_name'),
        }
    }

def bulk_email_lookup(emails: list, output_file: str = None) -> dict:
    """Lookup domains for multiple emails"""
    results = {}
    total = len(emails)

    for i, email in enumerate(emails, 1):
        email = email.strip().lower()
        if not email or '@' not in email:
            continue

        log(f"[{i}/{total}] Looking up: {email}")
        domains = get_all_domains_by_email(email)

        if domains:
            results[email] = {
                'total_domains': len(domains),
                'domains': [d.get('domain_name') for d in domains],
                'registrars': list(set(d.get('domain_registrar', {}).get('registrar_name', '') for d in domains)),
                'raw_data': domains
            }
            log(f"Found {len(domains)} domains", 'success')
        else:
            results[email] = {'total_domains': 0, 'domains': []}
            log("No domains found", 'warning')

    # Save results
    if output_file:
        with open(output_file, 'w', encoding='utf-8') as f:
            json.dump(results, f, indent=2, ensure_ascii=False)
        log(f"Results saved to: {output_file}", 'success')

    return results

def export_to_csv(results: dict, filename: str) -> None:
    """Export results to CSV"""
    with open(filename, 'w', newline='', encoding='utf-8') as f:
        writer = csv.writer(f)
        writer.writerow(['email', 'domain', 'registrar', 'created', 'expires'])

        for email, data in results.items():
            for domain_data in data.get('raw_data', []):
                writer.writerow([
                    email,
                    domain_data.get('domain_name', ''),
                    domain_data.get('domain_registrar', {}).get('registrar_name', ''),
                    domain_data.get('create_date', ''),
                    domain_data.get('expiry_date', '')
                ])

    log(f"CSV exported to: {filename}", 'success')

def main():
    parser = argparse.ArgumentParser(
        description='Whoxy.com WHOIS & Reverse WHOIS Lookup Tool',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python whoxy_lookup.py whois example.com
  python whoxy_lookup.py email scammer@gmail.com
  python whoxy_lookup.py name "John Scammer"
  python whoxy_lookup.py company "Scam Corp Ltd"
  python whoxy_lookup.py bulk-email emails.txt --output results.json
        """
    )

    subparsers = parser.add_subparsers(dest='command', help='Commands')

    # WHOIS command
    whois_parser = subparsers.add_parser('whois', help='WHOIS lookup for a domain')
    whois_parser.add_argument('domain', help='Domain to lookup')

    # Email reverse lookup
    email_parser = subparsers.add_parser('email', help='Find domains by registrant email')
    email_parser.add_argument('email', help='Email address to search')
    email_parser.add_argument('--output', '-o', help='Output file (JSON)')

    # Name reverse lookup
    name_parser = subparsers.add_parser('name', help='Find domains by registrant name')
    name_parser.add_argument('name', help='Name to search')
    name_parser.add_argument('--output', '-o', help='Output file (JSON)')

    # Company reverse lookup
    company_parser = subparsers.add_parser('company', help='Find domains by company name')
    company_parser.add_argument('company', help='Company to search')
    company_parser.add_argument('--output', '-o', help='Output file (JSON)')

    # Bulk email lookup
    bulk_parser = subparsers.add_parser('bulk-email', help='Lookup domains for multiple emails')
    bulk_parser.add_argument('file', help='File with emails (one per line)')
    bulk_parser.add_argument('--output', '-o', default='whoxy_results.json', help='Output JSON file')
    bulk_parser.add_argument('--csv', help='Also export to CSV')

    args = parser.parse_args()

    if not args.command:
        parser.print_help()
        sys.exit(1)

    if args.command == 'whois':
        data = whois_lookup(args.domain)
        if data:
            formatted = format_whois_result(data)
            print(json.dumps(formatted, indent=2))

    elif args.command == 'email':
        domains = get_all_domains_by_email(args.email)
        if domains:
            log(f"Found {len(domains)} domains registered by {args.email}:", 'success')
            for d in domains[:20]:  # Show first 20
                print(f"  - {d.get('domain_name')} ({d.get('create_date', 'N/A')})")
            if len(domains) > 20:
                print(f"  ... and {len(domains) - 20} more")

            if args.output:
                with open(args.output, 'w', encoding='utf-8') as f:
                    json.dump(domains, f, indent=2, ensure_ascii=False)
                log(f"Full results saved to: {args.output}", 'success')
        else:
            log("No domains found", 'warning')

    elif args.command in ('name', 'company'):
        search_type = args.command
        query = getattr(args, search_type)
        data = reverse_whois(search_type, query)

        if data:
            domains = data.get('search_result', [])
            total = data.get('total_results', 0)
            log(f"Found {total} domains:", 'success')

            for d in domains[:20]:
                print(f"  - {d.get('domain_name')} ({d.get('create_date', 'N/A')})")
            if total > 20:
                print(f"  ... and {total - 20} more (use --output to save all)")

            if args.output:
                with open(args.output, 'w', encoding='utf-8') as f:
                    json.dump(data, f, indent=2, ensure_ascii=False)
                log(f"Results saved to: {args.output}", 'success')

    elif args.command == 'bulk-email':
        if not Path(args.file).exists():
            log(f"File not found: {args.file}", 'error')
            sys.exit(1)

        with open(args.file, 'r') as f:
            emails = [line.strip() for line in f if line.strip() and '@' in line]

        log(f"Loaded {len(emails)} emails", 'info')
        results = bulk_email_lookup(emails, args.output)

        total_domains = sum(r.get('total_domains', 0) for r in results.values())
        log(f"Total: {total_domains} domains across {len(results)} emails", 'success')

        if args.csv:
            export_to_csv(results, args.csv)

if __name__ == '__main__':
    main()
