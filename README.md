# URL Reputation Checker

Multi-source URL/domain security analysis with aggregated risk scoring.

## Features

- **7 reputation sources**: VirusTotal, URLScan.io, Google Safe Browsing, AbuseIPDB, URLhaus, PhishTank/OpenPhish, DNSBL
- **Works without API keys**: Free sources (URLhaus, PhishTank, DNSBL) always available
- **Parallel checking**: Fast concurrent checks across all sources
- **Aggregated risk score**: 0-100 score with verdict (CLEAN, LOW_RISK, MEDIUM_RISK, HIGH_RISK)

## Quick Start

### Using uvx (recommended)

```bash
# Run directly without installation
uvx --from git+https://github.com/newuni/url-reputation url-reputation "https://example.com"

# With JSON output
uvx --from git+https://github.com/newuni/url-reputation url-reputation "https://example.com" --json
```

### Using pip

```bash
# From GitHub
pip install git+https://github.com/newuni/url-reputation

# From wheel (download from releases)
pip install url_reputation-1.0.0-py3-none-any.whl
```

### Download wheel

📦 [Download wheel from releases](https://github.com/newuni/url-reputation/releases/latest)

```bash
# Download and install
curl -LO https://github.com/newuni/url-reputation/releases/download/v1.0.0/url_reputation-1.0.0-py3-none-any.whl
pip install url_reputation-1.0.0-py3-none-any.whl
url-reputation "https://example.com"
```

### Using the script directly

```bash
git clone https://github.com/newuni/url-reputation
cd url-reputation
python3 scripts/check_url.py "https://example.com"
```

## Usage Examples

### Check a clean URL

```bash
$ url-reputation "https://google.com"

🔍 URL Reputation Report
==================================================
URL:    https://google.com
Domain: google.com
==================================================

✅ Verdict: CLEAN
📊 Risk Score: 0/100

📋 Source Results:
--------------------------------------------------
  urlhaus: ✅ Clean
  phishtank: ✅ Clean
  dnsbl: ✅ Clean

⏱️  Checked at: 2026-01-20T19:13:22.562378+00:00
```

### JSON output

```bash
$ url-reputation "https://google.com" --json
```

```json
{
  "url": "https://google.com",
  "domain": "google.com",
  "risk_score": 0,
  "verdict": "CLEAN",
  "checked_at": "2026-01-20T19:13:22.562378+00:00",
  "sources": {
    "urlhaus": {
      "listed": false
    },
    "phishtank": {
      "listed": false
    },
    "dnsbl": {
      "listed": false,
      "details": {
        "spamhaus_dbl": {"listed": false},
        "surbl": {"listed": false},
        "spamhaus_zen": {"listed": false, "ip": "216.58.206.78"}
      }
    }
  }
}
```

### Check specific sources only

```bash
url-reputation "https://example.com" --sources urlhaus,dnsbl
```

### With API keys for premium sources

```bash
export VIRUSTOTAL_API_KEY="your-key"
url-reputation "https://suspicious-site.com"
```

## API Keys (Optional)

Set environment variables for premium sources:

| Source | Environment Variable | Free Tier |
|--------|---------------------|-----------|
| VirusTotal | `VIRUSTOTAL_API_KEY` | 4 req/min |
| URLScan.io | `URLSCAN_API_KEY` | 5000/day |
| Google Safe Browsing | `GOOGLE_SAFEBROWSING_API_KEY` | 10k/day |
| AbuseIPDB | `ABUSEIPDB_API_KEY` | 1000/day |

See `references/api_setup.md` for detailed instructions on obtaining API keys.

## Free Sources (No API Key Needed)

These sources work without any API key:

| Source | Data | Update Frequency |
|--------|------|------------------|
| URLhaus | Malware URLs from abuse.ch | Every 5 minutes |
| OpenPhish | Phishing URLs | Hourly |
| DNSBL | Spamhaus DBL, SURBL, Spamhaus ZEN | Real-time DNS |

## Risk Scoring

| Score | Verdict | Meaning |
|-------|---------|---------|
| 0-20 | CLEAN | No threats detected |
| 21-50 | LOW_RISK | Minor concerns, likely safe |
| 51-75 | MEDIUM_RISK | Suspicious, investigate further |
| 76-100 | HIGH_RISK | Likely malicious, avoid |

## Python API

```python
from url_reputation import check_url_reputation

result = check_url_reputation("https://example.com")
print(f"Verdict: {result['verdict']} ({result['risk_score']}/100)")

# With specific sources
result = check_url_reputation(
    "https://example.com",
    sources=["urlhaus", "dnsbl"],
    timeout=15
)
```

## As a Clawdbot Skill

Copy or symlink this folder to your Clawdbot skills directory to use it as an agent skill.

## Running Tests

```bash
# Run all tests
python3 -m unittest discover tests/

# Run specific test file
python3 -m unittest tests.test_checker

# With pytest (if installed)
pytest tests/ -v
```

## License

MIT
