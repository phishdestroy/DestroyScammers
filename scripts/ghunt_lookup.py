#!/usr/bin/env python3
"""
GHunt Email OSINT Tool
======================
Lookup Google account information using GHunt

Prerequisites:
1. Install GHunt: pip install ghunt
2. Setup GHunt: ghunt login
   (This opens browser to authenticate with Google)

Features:
- Google account profile lookup
- Profile picture extraction
- Google Maps reviews
- Google Calendar events
- YouTube channel info

Usage:
    python ghunt_lookup.py email <email@gmail.com>
    python ghunt_lookup.py bulk <emails.txt> --output results.json

Note: GHunt requires authentication setup first.
Run 'ghunt login' before using this script.
"""

import os
import sys
import json
import subprocess
import argparse
from datetime import datetime
from pathlib import Path

def log(msg: str, level: str = 'info') -> None:
    """Print colored log message"""
    colors = {
        'info': '\033[94m[*]\033[0m',
        'success': '\033[92m[+]\033[0m',
        'warning': '\033[93m[!]\033[0m',
        'error': '\033[91m[-]\033[0m'
    }
    print(f"{colors.get(level, '[*]')} {msg}")

def check_ghunt_installed() -> bool:
    """Check if GHunt is installed"""
    try:
        result = subprocess.run(['ghunt', '--help'], capture_output=True, text=True)
        return result.returncode == 0
    except FileNotFoundError:
        return False

def check_ghunt_auth() -> bool:
    """Check if GHunt is authenticated"""
    ghunt_dir = Path.home() / '.ghunt'
    creds_file = ghunt_dir / 'creds.m'
    return creds_file.exists()

def setup_instructions():
    """Print GHunt setup instructions"""
    print("""
╔══════════════════════════════════════════════════════════════╗
║                    GHunt Setup Instructions                   ║
╠══════════════════════════════════════════════════════════════╣
║                                                               ║
║  1. Install GHunt:                                            ║
║     pip install ghunt                                         ║
║                                                               ║
║  2. Login to GHunt (opens browser):                           ║
║     ghunt login                                               ║
║                                                               ║
║  3. Follow browser prompts to authenticate                    ║
║                                                               ║
║  After setup, you can use this script normally.               ║
║                                                               ║
║  GHunt GitHub: https://github.com/mxrch/GHunt                 ║
║                                                               ║
╚══════════════════════════════════════════════════════════════╝
""")

def lookup_email(email: str) -> dict | None:
    """Lookup Google account by email using GHunt"""
    if not check_ghunt_installed():
        log("GHunt not installed. Run: pip install ghunt", 'error')
        return None

    if not check_ghunt_auth():
        log("GHunt not authenticated. Run: ghunt login", 'error')
        setup_instructions()
        return None

    log(f"Looking up: {email}", 'info')

    try:
        # Run ghunt email command
        result = subprocess.run(
            ['ghunt', 'email', email, '--json'],
            capture_output=True,
            text=True,
            timeout=60
        )

        if result.returncode == 0 and result.stdout:
            try:
                data = json.loads(result.stdout)
                return data
            except json.JSONDecodeError:
                # Parse text output if JSON fails
                return parse_text_output(result.stdout, email)
        else:
            log(f"GHunt error: {result.stderr[:200] if result.stderr else 'Unknown'}", 'error')
            return None

    except subprocess.TimeoutExpired:
        log("GHunt timeout (60s)", 'error')
        return None
    except Exception as e:
        log(f"Error: {e}", 'error')
        return None

def parse_text_output(output: str, email: str) -> dict:
    """Parse GHunt text output into structured data"""
    result = {
        'email': email,
        'found': False,
        'raw_output': output
    }

    if 'not found' in output.lower() or 'no google account' in output.lower():
        return result

    result['found'] = True

    # Try to extract common fields
    lines = output.split('\n')
    for line in lines:
        line = line.strip()

        if 'Name:' in line:
            result['name'] = line.split('Name:')[-1].strip()
        elif 'Profile Picture:' in line or 'Photo:' in line:
            url = line.split(':', 1)[-1].strip()
            if url.startswith('http'):
                result['photo'] = url
        elif 'Last Edit:' in line or 'Updated:' in line:
            result['last_edit'] = line.split(':', 1)[-1].strip()
        elif 'Gaia ID:' in line or 'ID:' in line:
            result['gaia_id'] = line.split(':', 1)[-1].strip()

    return result

def bulk_lookup(emails: list, output_file: str = None) -> dict:
    """Lookup multiple emails"""
    if not check_ghunt_installed():
        log("GHunt not installed. Run: pip install ghunt", 'error')
        setup_instructions()
        return {}

    if not check_ghunt_auth():
        log("GHunt not authenticated. Run: ghunt login", 'error')
        setup_instructions()
        return {}

    results = {}
    total = len(emails)
    found_count = 0

    for i, email in enumerate(emails, 1):
        email = email.strip().lower()
        if not email or '@' not in email:
            continue

        log(f"[{i}/{total}] Looking up: {email}")
        data = lookup_email(email)

        if data:
            results[email] = data
            if data.get('found'):
                found_count += 1
                log(f"Found: {data.get('name', 'Unknown')}", 'success')
            else:
                log("Not found", 'warning')
        else:
            results[email] = {'email': email, 'found': False, 'error': 'Lookup failed'}

    # Save results
    if output_file:
        with open(output_file, 'w', encoding='utf-8') as f:
            json.dump(results, f, indent=2, ensure_ascii=False)
        log(f"Results saved to: {output_file}", 'success')

    log(f"\nSummary: Found {found_count}/{len(results)} accounts", 'success')
    return results

def main():
    parser = argparse.ArgumentParser(
        description='GHunt Email OSINT Tool',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Prerequisites:
  pip install ghunt
  ghunt login

Examples:
  python ghunt_lookup.py email scammer@gmail.com
  python ghunt_lookup.py bulk emails.txt --output ghunt_results.json
  python ghunt_lookup.py setup
        """
    )

    subparsers = parser.add_subparsers(dest='command', help='Commands')

    # Email command
    email_parser = subparsers.add_parser('email', help='Lookup single email')
    email_parser.add_argument('email', help='Gmail address to lookup')
    email_parser.add_argument('--output', '-o', help='Save result to JSON file')

    # Bulk command
    bulk_parser = subparsers.add_parser('bulk', help='Lookup multiple emails')
    bulk_parser.add_argument('file', help='File with emails (one per line)')
    bulk_parser.add_argument('--output', '-o', default='ghunt_results.json', help='Output file')

    # Setup command
    subparsers.add_parser('setup', help='Show setup instructions')

    args = parser.parse_args()

    if not args.command:
        parser.print_help()
        sys.exit(1)

    if args.command == 'setup':
        setup_instructions()

    elif args.command == 'email':
        data = lookup_email(args.email)
        if data:
            print(json.dumps(data, indent=2))
            if args.output:
                with open(args.output, 'w', encoding='utf-8') as f:
                    json.dump(data, f, indent=2, ensure_ascii=False)
                log(f"Saved to: {args.output}", 'success')

    elif args.command == 'bulk':
        if not Path(args.file).exists():
            log(f"File not found: {args.file}", 'error')
            sys.exit(1)

        with open(args.file, 'r') as f:
            emails = [line.strip() for line in f if line.strip() and '@' in line]

        log(f"Loaded {len(emails)} emails", 'info')
        bulk_lookup(emails, args.output)

if __name__ == '__main__':
    main()
