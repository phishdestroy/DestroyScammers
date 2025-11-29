#!/usr/bin/env python3
"""
Web Archive (Wayback Machine) Lookup Tool
==========================================
Find archived snapshots of websites on archive.org

Features:
- Check if domain/URL was archived
- Get all available snapshots
- Download specific snapshots
- Bulk check domains
- Save archived pages

Usage:
    python webarchive_lookup.py check <url>
    python webarchive_lookup.py snapshots <url> [--year 2023]
    python webarchive_lookup.py download <url> [--timestamp 20230115]
    python webarchive_lookup.py bulk <urls.txt> --output archived.json
"""

import os
import sys
import json
import time
import argparse
import requests
from datetime import datetime
from pathlib import Path
from urllib.parse import urlparse, quote

BASE_URL = 'https://archive.org/wayback/available'
CDX_URL = 'https://web.archive.org/cdx/search/cdx'

def log(msg: str, level: str = 'info') -> None:
    """Print colored log message"""
    colors = {
        'info': '\033[94m[*]\033[0m',
        'success': '\033[92m[+]\033[0m',
        'warning': '\033[93m[!]\033[0m',
        'error': '\033[91m[-]\033[0m'
    }
    print(f"{colors.get(level, '[*]')} {msg}")

def normalize_url(url: str) -> str:
    """Ensure URL has scheme"""
    if not url.startswith(('http://', 'https://')):
        url = 'https://' + url
    return url

def check_availability(url: str) -> dict | None:
    """Check if URL has been archived"""
    url = normalize_url(url)

    try:
        response = requests.get(
            BASE_URL,
            params={'url': url},
            timeout=30
        )
        if response.status_code == 200:
            data = response.json()
            snapshot = data.get('archived_snapshots', {}).get('closest')
            if snapshot:
                return {
                    'available': True,
                    'url': snapshot.get('url'),
                    'timestamp': snapshot.get('timestamp'),
                    'status': snapshot.get('status')
                }
            return {'available': False}
        else:
            log(f"API error: {response.status_code}", 'error')
            return None
    except Exception as e:
        log(f"Request error: {e}", 'error')
        return None

def get_snapshots(url: str, year: str = None, limit: int = 100) -> list:
    """Get all available snapshots for a URL"""
    url = normalize_url(url)

    params = {
        'url': url,
        'output': 'json',
        'limit': limit,
        'fl': 'timestamp,original,statuscode,mimetype,length'
    }

    if year:
        params['from'] = f'{year}0101'
        params['to'] = f'{year}1231'

    try:
        response = requests.get(CDX_URL, params=params, timeout=60)
        if response.status_code == 200:
            lines = response.text.strip().split('\n')
            if len(lines) <= 1:
                return []

            # First line is header
            results = []
            for line in lines[1:]:
                try:
                    data = json.loads(line) if line.startswith('[') else line.split()
                    if len(data) >= 5:
                        results.append({
                            'timestamp': data[0],
                            'original': data[1],
                            'status': data[2],
                            'mimetype': data[3],
                            'length': data[4] if len(data) > 4 else '0',
                            'archive_url': f"https://web.archive.org/web/{data[0]}/{data[1]}"
                        })
                except:
                    continue

            return results
        else:
            log(f"CDX API error: {response.status_code}", 'error')
            return []
    except Exception as e:
        log(f"Request error: {e}", 'error')
        return []

def get_snapshot_content(url: str, timestamp: str = None) -> str | None:
    """Download content from a specific snapshot"""
    url = normalize_url(url)

    if timestamp:
        archive_url = f"https://web.archive.org/web/{timestamp}id_/{url}"
    else:
        archive_url = f"https://web.archive.org/web/{url}"

    try:
        response = requests.get(archive_url, timeout=60)
        if response.status_code == 200:
            return response.text
        else:
            log(f"Download failed: {response.status_code}", 'error')
            return None
    except Exception as e:
        log(f"Download error: {e}", 'error')
        return None

def bulk_check(urls: list, output_file: str = None) -> dict:
    """Check archive availability for multiple URLs"""
    results = {}
    total = len(urls)

    for i, url in enumerate(urls, 1):
        url = url.strip()
        if not url:
            continue

        log(f"[{i}/{total}] Checking: {url}")
        data = check_availability(url)

        if data and data.get('available'):
            results[url] = {
                'archived': True,
                'archive_url': data.get('url'),
                'timestamp': data.get('timestamp'),
                'date': datetime.strptime(data['timestamp'], '%Y%m%d%H%M%S').strftime('%Y-%m-%d %H:%M:%S') if data.get('timestamp') else None
            }
            log(f"Archived on {results[url]['date']}", 'success')
        else:
            results[url] = {'archived': False}
            log("Not archived", 'warning')

        time.sleep(1)  # Be nice to the API

    # Save results
    if output_file:
        with open(output_file, 'w', encoding='utf-8') as f:
            json.dump(results, f, indent=2, ensure_ascii=False)
        log(f"Results saved to: {output_file}", 'success')

    archived_count = sum(1 for r in results.values() if r.get('archived'))
    log(f"\nSummary: {archived_count}/{len(results)} URLs archived", 'success')

    return results

def save_snapshot(url: str, timestamp: str = None, output_dir: str = '.') -> bool:
    """Save a snapshot to file"""
    content = get_snapshot_content(url, timestamp)
    if not content:
        return False

    # Create filename from URL
    parsed = urlparse(normalize_url(url))
    domain = parsed.netloc.replace('.', '_')
    ts = timestamp or 'latest'
    filename = f"{domain}_{ts}.html"
    filepath = Path(output_dir) / filename

    with open(filepath, 'w', encoding='utf-8') as f:
        f.write(content)

    log(f"Saved to: {filepath}", 'success')
    return True

def main():
    parser = argparse.ArgumentParser(
        description='Web Archive (Wayback Machine) Lookup Tool',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python webarchive_lookup.py check example.com
  python webarchive_lookup.py snapshots phishing-site.com --year 2023
  python webarchive_lookup.py download scam-site.com --timestamp 20230115120000
  python webarchive_lookup.py bulk urls.txt --output archived.json
        """
    )

    subparsers = parser.add_subparsers(dest='command', help='Commands')

    # Check command
    check_parser = subparsers.add_parser('check', help='Check if URL is archived')
    check_parser.add_argument('url', help='URL to check')

    # Snapshots command
    snap_parser = subparsers.add_parser('snapshots', help='Get all snapshots')
    snap_parser.add_argument('url', help='URL to lookup')
    snap_parser.add_argument('--year', '-y', help='Filter by year (e.g., 2023)')
    snap_parser.add_argument('--limit', '-l', type=int, default=50, help='Max results')

    # Download command
    dl_parser = subparsers.add_parser('download', help='Download archived page')
    dl_parser.add_argument('url', help='URL to download')
    dl_parser.add_argument('--timestamp', '-t', help='Specific timestamp (YYYYMMDDhhmmss)')
    dl_parser.add_argument('--output', '-o', default='.', help='Output directory')

    # Bulk command
    bulk_parser = subparsers.add_parser('bulk', help='Check multiple URLs')
    bulk_parser.add_argument('file', help='File with URLs (one per line)')
    bulk_parser.add_argument('--output', '-o', default='archive_results.json', help='Output file')

    args = parser.parse_args()

    if not args.command:
        parser.print_help()
        sys.exit(1)

    if args.command == 'check':
        data = check_availability(args.url)
        if data:
            if data.get('available'):
                log(f"URL is archived!", 'success')
                print(f"  Archive URL: {data.get('url')}")
                print(f"  Timestamp: {data.get('timestamp')}")
                if data.get('timestamp'):
                    dt = datetime.strptime(data['timestamp'], '%Y%m%d%H%M%S')
                    print(f"  Date: {dt.strftime('%Y-%m-%d %H:%M:%S')}")
            else:
                log("URL not found in archive", 'warning')

    elif args.command == 'snapshots':
        snapshots = get_snapshots(args.url, args.year, args.limit)
        if snapshots:
            log(f"Found {len(snapshots)} snapshots:", 'success')
            for snap in snapshots[:20]:
                ts = snap.get('timestamp', '')
                if ts:
                    dt = datetime.strptime(ts, '%Y%m%d%H%M%S').strftime('%Y-%m-%d')
                else:
                    dt = 'Unknown'
                print(f"  - {dt}: {snap.get('archive_url')}")

            if len(snapshots) > 20:
                print(f"  ... and {len(snapshots) - 20} more")
        else:
            log("No snapshots found", 'warning')

    elif args.command == 'download':
        log(f"Downloading snapshot for: {args.url}")
        save_snapshot(args.url, args.timestamp, args.output)

    elif args.command == 'bulk':
        if not Path(args.file).exists():
            log(f"File not found: {args.file}", 'error')
            sys.exit(1)

        with open(args.file, 'r') as f:
            urls = [line.strip() for line in f if line.strip()]

        log(f"Loaded {len(urls)} URLs", 'info')
        bulk_check(urls, args.output)

if __name__ == '__main__':
    main()
