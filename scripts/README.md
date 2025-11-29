# OSINT Scripts Collection

A collection of standalone Python scripts for threat intelligence gathering and domain analysis.

## Quick Start

```bash
# 1. Copy env example and add your API keys
cp .env.example .env

# 2. Install dependencies
pip install requests python-dotenv

# 3. Run any script
python urlscan_search.py search example.com
```

## Scripts Overview

| Script | Description | API Key Required |
|--------|-------------|------------------|
| `urlscan_search.py` | Search & scan domains via URLScan.io | Yes (free tier) |
| `whoxy_lookup.py` | WHOIS & reverse WHOIS lookups | Yes (paid) |
| `virustotal_scan.py` | Check domains against 70+ AV engines | Yes (free tier) |
| `webarchive_lookup.py` | Find archived website snapshots | No |
| `blocklist_checker.py` | Check against public phishing blocklists | No |
| `ghunt_lookup.py` | Google account OSINT via GHunt | No (needs auth) |

---

## URLScan.io Search (`urlscan_search.py`)

Search for existing scans or submit new domains for scanning.

```bash
# Search existing scans
python urlscan_search.py search malicious-site.com

# Submit new scan
python urlscan_search.py scan phishing-site.com

# Submit private scan
python urlscan_search.py scan phishing-site.com --private

# Bulk scan from file
python urlscan_search.py bulk domains.txt --output results.json
```

**API Limits (Free Tier):**
- Public Scans: 60/min, 500/hour, 5,000/day
- Search Requests: 120/min, 1000/hour, 10,000/day

---

## Whoxy WHOIS Lookup (`whoxy_lookup.py`)

Domain WHOIS data and reverse WHOIS searches.

```bash
# Standard WHOIS lookup
python whoxy_lookup.py whois example.com

# Find all domains by email
python whoxy_lookup.py email scammer@gmail.com --output domains.json

# Find domains by registrant name
python whoxy_lookup.py name "John Scammer"

# Find domains by company
python whoxy_lookup.py company "Scam Corp Ltd"

# Bulk email lookup
python whoxy_lookup.py bulk-email emails.txt --output results.json --csv results.csv
```

---

## VirusTotal Scanner (`virustotal_scan.py`)

Check domains/URLs/IPs against 70+ antivirus engines.

```bash
# Check domain reputation
python virustotal_scan.py domain malicious-site.com

# Scan a URL
python virustotal_scan.py url https://phishing-site.com/login

# Check IP reputation
python virustotal_scan.py ip 1.2.3.4

# Bulk scan domains
python virustotal_scan.py bulk domains.txt --output vt_results.json
```

**API Limits (Free Tier):**
- 4 requests/minute
- 500 requests/day

---

## Web Archive Lookup (`webarchive_lookup.py`)

Find archived snapshots of websites on archive.org.

```bash
# Check if domain was archived
python webarchive_lookup.py check suspicious-site.com

# Get all snapshots (optionally filter by year)
python webarchive_lookup.py snapshots phishing-site.com --year 2023

# Download archived page
python webarchive_lookup.py download scam-site.com --timestamp 20230115120000

# Bulk check URLs
python webarchive_lookup.py bulk urls.txt --output archived.json
```

**No API key required!**

---

## Blocklist Checker (`blocklist_checker.py`)

Check domains against multiple public phishing/scam blocklists.

**Sources:**
- MetaMask eth-phishing-detect
- ScamSniffer database
- Polkadot phishing list
- CryptoFirewall blocklist
- OpenPhish feed
- PhishDestroy list
- SEAL blocklists
- Enkrypt blocklist

```bash
# Update local blocklist cache
python blocklist_checker.py update

# Check single domain
python blocklist_checker.py check suspicious-site.com

# Bulk check domains
python blocklist_checker.py bulk domains.txt --output blocked.json

# Show statistics
python blocklist_checker.py stats
```

**No API key required!**

---

## GHunt Lookup (`ghunt_lookup.py`)

Google account OSINT using GHunt.

### Setup Required:
```bash
# Install GHunt
pip install ghunt

# Login (opens browser for Google auth)
ghunt login
```

### Usage:
```bash
# Show setup instructions
python ghunt_lookup.py setup

# Lookup single email
python ghunt_lookup.py email scammer@gmail.com

# Bulk lookup
python ghunt_lookup.py bulk emails.txt --output ghunt_results.json
```

---

## Environment Variables

Copy `.env.example` to `.env` and fill in your API keys:

```env
URLSCAN_API_KEY=your_key_here
WHOXY_API_KEY=your_key_here
VIRUSTOTAL_API_KEY=your_key_here
ABUSEIPDB_API_KEY=your_key_here
SHODAN_API_KEY=your_key_here
```

### Getting API Keys:

| Service | URL | Pricing |
|---------|-----|---------|
| URLScan.io | https://urlscan.io/user/profile | Free tier available |
| Whoxy | https://www.whoxy.com/account | Paid ($2 for 500 queries) |
| VirusTotal | https://www.virustotal.com/gui/my-apikey | Free tier available |
| AbuseIPDB | https://www.abuseipdb.com/account/api | Free tier (1000/day) |
| Shodan | https://account.shodan.io/ | Free tier available |

---

## Output Formats

All scripts support JSON output with `--output` flag:

```bash
python urlscan_search.py bulk domains.txt --output results.json
```

Some scripts also support CSV:
```bash
python whoxy_lookup.py bulk-email emails.txt --output results.json --csv results.csv
```

---

## Integration with Dashboard

Results from these scripts can be imported into the main OSINT Dashboard:

```bash
# Scan actor domains
python urlscan_search.py bulk actor_domains.txt --output scans.json

# Check against blocklists
python blocklist_checker.py bulk actor_domains.txt --output blocked.json

# Then import results to dashboard data
# (integration scripts coming soon)
```

---

## Error Handling

All scripts include:
- Colored console output
- Rate limiting handling
- Timeout protection
- Graceful error recovery

---

## Contributing

Feel free to add new OSINT source scripts. Follow the existing pattern:
1. Create `newservice_lookup.py`
2. Use `dotenv` for API keys
3. Support `--output` flag for JSON
4. Add documentation to this README
