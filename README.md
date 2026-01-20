# URL Reputation Checker

Multi-source URL/domain security analysis with aggregated risk scoring.

## Features

- **7 reputation sources**: VirusTotal, URLScan.io, Google Safe Browsing, AbuseIPDB, URLhaus, PhishTank, DNSBL
- **Works without API keys**: Free sources (URLhaus, PhishTank, DNSBL) always available
- **Parallel checking**: Fast results from all sources
- **Aggregated risk score**: 0-100 score with verdict (CLEAN, LOW_RISK, MEDIUM_RISK, HIGH_RISK)

## Quick Start

```bash
# Check a URL (uses all available sources)
python3 scripts/check_url.py "https://example.com"

# JSON output
python3 scripts/check_url.py "https://example.com" --json

# Specific sources only
python3 scripts/check_url.py "https://example.com" --sources urlhaus,phishtank,dnsbl
```

## API Keys (Optional)

Set environment variables for premium sources:

```bash
export VIRUSTOTAL_API_KEY="your-key"
export URLSCAN_API_KEY="your-key"
export GOOGLE_SAFEBROWSING_API_KEY="your-key"
export ABUSEIPDB_API_KEY="your-key"
```

See `references/api_setup.md` for detailed instructions.

## As a Clawdbot Skill

Copy or symlink this folder to your Clawdbot skills directory to use it as an agent skill.

## License

MIT
