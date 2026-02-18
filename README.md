# URL Reputation Checker

Multi-source URL/domain security analysis with aggregated risk scoring.

## Features

- **10 reputation sources**: VirusTotal, URLScan.io, Google Safe Browsing, AbuseIPDB, URLhaus, PhishTank/OpenPhish, DNSBL, AlienVault OTX, IPQualityScore, ThreatFox
- **Works without API keys**: Free sources (URLhaus, OpenPhish, DNSBL, AlienVault OTX) always available
- **Parallel checking**: Fast concurrent checks across all sources
- **Aggregated risk score**: 0-100 score with verdict (CLEAN, LOW_RISK, MEDIUM_RISK, HIGH_RISK)
- **Explainable scoring**: `score_breakdown[]` + `reasons[]` (optional provider weights via `URL_REPUTATION_PROVIDER_WEIGHTS`)
- **Enrichment**: DNS/Whois + `asn_geo` (ASN + basic geo with quality report)

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
pip install url_reputation-<VERSION>-py3-none-any.whl
```

### Download wheel

📦 [Download wheel from releases](https://github.com/newuni/url-reputation/releases/latest)

For release history and migration notes, see [CHANGELOG.md](CHANGELOG.md).

```bash
# Download latest wheel and install
gh release download --repo newuni/url-reputation --pattern "*.whl" --clobber
pip install url_reputation-*.whl
url-reputation "https://example.com"
```

### Using the script directly

```bash
git clone https://github.com/newuni/url-reputation
cd url-reputation
python3 scripts/check_url.py "https://example.com"
```

## 🧑‍💻 Development

See [DEVELOPMENT.md](DEVELOPMENT.md) for Docker-based dev + running tests.

## 🐳 Docker Deployment

Run the web UI with Docker for a visual interface accessible from any browser.

### Quick Start

```bash
git clone https://github.com/newuni/url-reputation
cd url-reputation
docker compose up -d
```

The web UI will be available at **http://localhost:8095**

### Custom Port

Edit `docker-compose.yml` to change the port:

```yaml
ports:
  - "8080:8000"  # Change 8095 to your preferred port
```

### With API Keys

Create a `.env` file or set environment variables in `docker-compose.yml`:

```yaml
environment:
  - VIRUSTOTAL_API_KEY=your-key-here
  - URLSCAN_API_KEY=your-key-here
```

### REST API Endpoints

The Docker container exposes a REST API:

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/api/health` | GET | Health check |
| `/api/check` | POST | Check single URL |
| `/api/batch` | POST | Check multiple URLs |
| `/api/sources` | GET | List available sources |

**Example: Check a URL**
```bash
curl -X POST http://localhost:8095/api/check \
  -H "Content-Type: application/json" \
  -d '{"url": "https://example.com", "enrich": ["dns", "whois"]}'
```

**Example: Batch check**
```bash
curl -X POST http://localhost:8095/api/batch \
  -H "Content-Type: application/json" \
  -d '{"urls": ["https://google.com", "https://github.com"]}'
```

**Response format (Schema v1):**
```json
{
  "schema_version": "1",
  "indicator": {
    "input": "https://example.com",
    "type": "url",
    "canonical": "https://example.com",
    "domain": "example.com"
  },
  "verdict": "CLEAN",
  "risk_score": 0,
  "score_breakdown": [],
  "reasons": [],
  "checked_at": "2026-02-17T13:00:00.000000+00:00",
  "sources": [
    {
      "name": "urlhaus",
      "status": "ok",
      "raw": {"listed": false}
    }
  ],
  "enrichment": {
    "dns": {"a_records": ["93.184.216.34"]},
    "whois": {"registrar": "..."},
    "asn_geo": {
      "ips": ["93.184.216.34"],
      "asn": {"number": 15133, "org": "EDGECAST", "prefix": "93.184.216.0/24"},
      "geo": {"country": "US"},
      "quality": {"source": "mixed", "confidence": "medium", "coverage": ["ips", "asn", "country"], "notes": [], "sources": ["ripe", "ip-api"]}
    }
  },
  "url": "https://example.com",
  "domain": "example.com"
}
```

## Usage Examples

### Explainable scoring (weights)

You can tweak how much each provider/enrichment contributes:

```bash
export URL_REPUTATION_PROVIDER_WEIGHTS='{"phishtank": 1.0, "virustotal": 1.2, "redirects": 0.5, "whois": 1.0}'
url-reputation "https://example.com" --enrich redirects,whois --json
```

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

### JSON output (Schema v1)

```bash
$ url-reputation "https://google.com" --json
```

### Markdown report output

```bash
# Single
url-reputation "https://google.com" --format markdown

# Batch (includes a summary at the end)
url-reputation --file urls.txt --format markdown
```

### Profiles (developer-friendly presets)

```bash
# Only providers that work without API keys
url-reputation "https://example.com" --profile free

# Try everything available (auto-skips providers missing API keys)
url-reputation "https://example.com" --profile thorough
```

### Cache (sqlite)

```bash
# Use default cache path (~/.cache/url-reputation/cache.sqlite)
url-reputation "https://example.com" --cache --cache-ttl 24h

# Custom cache path
url-reputation "https://example.com" --cache /tmp/urlrep.sqlite --cache-ttl 10m
```

### Legacy JSON compatibility

```bash
# Include `sources_map` for older consumers
url-reputation "https://example.com" --json --legacy-json
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

### Batch processing from file

```bash
# Create a file with URLs (one per line)
cat > urls.txt << EOF
# Comments are ignored
https://google.com
https://wikipedia.org
https://github.com
EOF

# Check all URLs
url-reputation --file urls.txt

# Output:
🔍 URL Reputation Batch Report
============================================================
Total URLs: 3

📊 Summary:
  ✅ CLEAN: 2
  ⚠️ LOW_RISK: 1

============================================================
📋 Results:
------------------------------------------------------------
  ✅ [  0/100] CLEAN        https://google.com
  ✅ [  0/100] CLEAN        https://wikipedia.org
  ⚠️ [ 40/100] LOW_RISK     https://github.com
```

```bash
# JSON output for batch
url-reputation --file urls.txt --json

# Control parallelism
url-reputation --file urls.txt --workers 10

# Limit batch work in CI
url-reputation --file urls.txt --format ndjson --max-requests 100
url-reputation --file urls.txt --format ndjson --budget-seconds 60

# Preserve input order (buffered) for streaming outputs
url-reputation --file urls.txt --format ndjson --preserve-order
```

### Check specific sources only

```bash
url-reputation "https://example.com" --sources urlhaus,dnsbl
```

### DNS, Whois & ASN/Geo enrichment

```bash
# Add DNS records and Whois info
url-reputation "https://example.com" --enrich dns,whois

# Add ASN + Geo (works best for domains/IPs)
url-reputation "example.com" --enrich asn_geo
url-reputation "1.1.1.1" --enrich asn

# DNS only
url-reputation "https://example.com" --enrich dns

# Output includes:
📋 Enrichment Data:
--------------------------------------------------

🌐 DNS Records:
  A:     93.184.216.34
  MX:    mail.example.com
  NS:    ns1.example.com, ns2.example.com
  SPF:   ✅  DMARC: ✅

📝 Whois:
  Created:   2001-01-01 (8500 days)
  Registrar: GoDaddy
  Country:   US

⚠️ Risk Indicators:
  • No SPF record
```

**Install enrichment dependencies:**
```bash
pip install url-reputation[full]
# Or manually: pip install dnspython python-whois
```

### Webhook notifications

```bash
# Send webhook on MEDIUM_RISK or HIGH_RISK (default)
url-reputation "https://suspicious.com" --webhook https://your-server.com/hook

# With HMAC secret for verification
url-reputation "https://suspicious.com" \
  --webhook https://your-server.com/hook \
  --webhook-secret "your-secret-key"

# Notify only on HIGH_RISK
url-reputation "https://suspicious.com" --webhook https://... --notify-on high

# Or via environment variables
export WEBHOOK_URL="https://your-server.com/hook"
export WEBHOOK_SECRET="your-secret-key"
url-reputation "https://suspicious.com"
```

**Webhook payload:**
```json
{
  "event": "url.risk_detected",
  "timestamp": 1737410000,
  "data": {
    "url": "https://suspicious.com",
    "domain": "suspicious.com",
    "risk_score": 75,
    "verdict": "MEDIUM_RISK",
    "sources": { ... }
  }
}
```

**Security headers:**
- `X-Timestamp`: Unix timestamp
- `X-Signature-256`: `sha256=HMAC(secret, timestamp.payload)`

### Webhook signature verification

Verify the signature on your server to ensure the request is authentic.

**Python:**
```python
import hmac, hashlib, time

def verify_webhook(payload: bytes, signature: str, timestamp: str, secret: str) -> bool:
    # Check timestamp (max 5 min old)
    if abs(time.time() - int(timestamp)) > 300:
        return False
    
    # Verify signature
    message = f"{timestamp}.{payload.decode()}"
    expected = "sha256=" + hmac.new(
        secret.encode(), message.encode(), hashlib.sha256
    ).hexdigest()
    
    return hmac.compare_digest(signature, expected)

# Flask example
@app.route('/webhook', methods=['POST'])
def webhook():
    if not verify_webhook(
        request.data,
        request.headers.get('X-Signature-256', ''),
        request.headers.get('X-Timestamp', ''),
        'your-secret'
    ):
        return 'Unauthorized', 401
    
    data = request.json
    # Process webhook...
```

**Node.js:**
```javascript
const crypto = require('crypto');

function verifyWebhook(payload, signature, timestamp, secret) {
  // Check timestamp (max 5 min old)
  if (Math.abs(Date.now() / 1000 - parseInt(timestamp)) > 300) {
    return false;
  }
  
  // Verify signature
  const message = `${timestamp}.${payload}`;
  const expected = 'sha256=' + crypto
    .createHmac('sha256', secret)
    .update(message)
    .digest('hex');
  
  return crypto.timingSafeEqual(
    Buffer.from(signature),
    Buffer.from(expected)
  );
}

// Express example
app.post('/webhook', (req, res) => {
  const valid = verifyWebhook(
    JSON.stringify(req.body),
    req.headers['x-signature-256'],
    req.headers['x-timestamp'],
    'your-secret'
  );
  
  if (!valid) return res.status(401).send('Unauthorized');
  // Process webhook...
});
```

**Go:**
```go
import (
    "crypto/hmac"
    "crypto/sha256"
    "encoding/hex"
    "fmt"
    "math"
    "strconv"
    "time"
)

func verifyWebhook(payload, signature, timestamp, secret string) bool {
    // Check timestamp
    ts, _ := strconv.ParseInt(timestamp, 10, 64)
    if math.Abs(float64(time.Now().Unix()-ts)) > 300 {
        return false
    }
    
    // Verify signature
    message := fmt.Sprintf("%s.%s", timestamp, payload)
    mac := hmac.New(sha256.New, []byte(secret))
    mac.Write([]byte(message))
    expected := "sha256=" + hex.EncodeToString(mac.Sum(nil))
    
    return hmac.Equal([]byte(signature), []byte(expected))
}
```

**PHP:**
```php
function verifyWebhook($payload, $signature, $timestamp, $secret) {
    // Check timestamp (max 5 min old)
    if (abs(time() - intval($timestamp)) > 300) {
        return false;
    }
    
    // Verify signature
    $message = $timestamp . '.' . $payload;
    $expected = 'sha256=' . hash_hmac('sha256', $message, $secret);
    
    return hash_equals($signature, $expected);
}

// Usage
$payload = file_get_contents('php://input');
$signature = $_SERVER['HTTP_X_SIGNATURE_256'] ?? '';
$timestamp = $_SERVER['HTTP_X_TIMESTAMP'] ?? '';

if (!verifyWebhook($payload, $signature, $timestamp, 'your-secret')) {
    http_response_code(401);
    exit('Unauthorized');
}
```

**Ruby:**
```ruby
require 'openssl'

def verify_webhook(payload, signature, timestamp, secret)
  # Check timestamp (max 5 min old)
  return false if (Time.now.to_i - timestamp.to_i).abs > 300
  
  # Verify signature
  message = "#{timestamp}.#{payload}"
  expected = "sha256=" + OpenSSL::HMAC.hexdigest('sha256', secret, message)
  
  Rack::Utils.secure_compare(signature, expected)
end
```

### With API keys for premium sources

```bash
export VIRUSTOTAL_API_KEY="your-key"
url-reputation "https://suspicious-site.com"
```

## API Keys (Optional)

Set environment variables for premium sources:

| Source | Environment Variable | Free Tier | Get API Key |
|--------|---------------------|-----------|-------------|
| VirusTotal | `VIRUSTOTAL_API_KEY` | 4 req/min | [virustotal.com](https://www.virustotal.com/gui/join-us) |
| URLScan.io | `URLSCAN_API_KEY` | 5000/day | [urlscan.io](https://urlscan.io/user/signup) |
| Google Safe Browsing | `GOOGLE_SAFEBROWSING_API_KEY` | 10k/day | [console.cloud.google.com](https://console.cloud.google.com/apis/library/safebrowsing.googleapis.com) |
| AbuseIPDB | `ABUSEIPDB_API_KEY` | 1000/day | [abuseipdb.com](https://www.abuseipdb.com/register) |
| IPQualityScore | `IPQUALITYSCORE_API_KEY` | 5000/month | [ipqualityscore.com](https://www.ipqualityscore.com/create-account) |
| ThreatFox | `THREATFOX_API_KEY` | Unlimited | [auth.abuse.ch](https://auth.abuse.ch/) |
| AlienVault OTX | `OTX_API_KEY` | Optional | [otx.alienvault.com](https://otx.alienvault.com/) |

### Using .env file (recommended)

```bash
# Copy the example file
cp .env.example .env

# Edit with your keys
nano .env
```

The tool automatically loads `.env` from:
1. Current directory
2. Home directory (`~/.env`)
3. `~/.urlreputation.env`

See `references/api_setup.md` for detailed instructions on obtaining API keys.

## Free Sources (No API Key Needed)

These sources work without any API key:

| Source | Data | Update Frequency | Website |
|--------|------|------------------|---------|
| URLhaus | Malware URLs | Every 5 min | [urlhaus.abuse.ch](https://urlhaus.abuse.ch/) |
| OpenPhish | Phishing URLs | Hourly | [openphish.com](https://openphish.com/) |
| DNSBL | Spam/malware domains | Real-time | [spamhaus.org](https://www.spamhaus.org/) / [surbl.org](https://surbl.org/) |
| AlienVault OTX | Threat intel, pulses | Real-time | [otx.alienvault.com](https://otx.alienvault.com/) |

## Risk Scoring

| Score | Verdict | Meaning |
|-------|---------|---------|
| 0-20 | CLEAN | No threats detected |
| 21-50 | LOW_RISK | Minor concerns, likely safe |
| 51-75 | MEDIUM_RISK | Suspicious, investigate further |
| 76-100 | HIGH_RISK | Likely malicious, avoid |

## Python API

```python
from url_reputation import check_url_reputation, check_urls_batch

# Single URL
result = check_url_reputation("https://example.com")
print(f"Verdict: {result['verdict']} ({result['risk_score']}/100)")

# Batch processing
urls = [
    "https://google.com",
    "https://wikipedia.org",
    "https://suspicious-site.com"
]
results = check_urls_batch(urls, max_workers=5)

for r in results:
    print(f"{r['verdict']}: {r['url']}")

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
pytest tests/ -v

# With coverage report
pytest tests/ --cov=url_reputation --cov-report=html

# Run specific test file
pytest tests/test_checker.py -v

# Property-based tests
pytest tests/test_properties.py -v

# Integration tests
pytest tests/test_integration.py -v

# Benchmarks only
pytest tests/bench/ --benchmark-only
```

See [CONTRIBUTING.md](CONTRIBUTING.md) for detailed test guidelines.

## Performance Benchmarks

### Run Benchmarks

```bash
# Install dev dependencies
pip install -e ".[dev]"

# Run benchmark suite
pytest tests/bench/ --benchmark-only

# Generate full report with charts
python scripts/run_benchmarks.py --output-dir results/
```

### Performance Comparison by Profile

| Profile | Providers | Avg Latency | Throughput | Best For |
|---------|-----------|-------------|------------|----------|
| `free` | 2-3 | ~100ms | ~800 ops/s | Quick checks, no API keys |
| `fast` | 3-4 | ~150ms | ~500 ops/s | General use |
| `thorough` | 8-10 | ~400ms | ~200 ops/s | Maximum coverage |

![Performance Chart](docs/performance/profile_comparison.png)

### Memory Usage

Expected memory usage for batch processing:

| URLs | Memory (no cache) | Memory (with cache) |
|------|-------------------|---------------------|
| 100 | ~15 MB | ~18 MB |
| 1,000 | ~45 MB | ~52 MB |
| 10,000 | ~120 MB | ~150 MB |

Run `python scripts/profile_memory.py` for detailed profiling.

## Provider Comparison

| Provider | Latency | Rate Limit | Cost/1k | Key Required |
|----------|---------|------------|---------|--------------|
| VirusTotal | ~300ms | 4/min free, 1k/day paid | $10 | ✅ |
| URLScan.io | ~500ms | 5k/day free | $0-20 | ✅ |
| Google Safe Browsing | ~100ms | 10k/day free | $0* | ✅ |
| URLhaus | ~150ms | Unlimited | Free | ❌ |
| DNSBL | ~50ms | Unlimited | Free | ❌ |
| AlienVault OTX | ~200ms | Unlimited | Free | Optional |

*Google Safe Browsing has free tier only

**Budget Recommendations:**
- **Low (Free)**: URLhaus, DNSBL, AlienVault OTX, PhishTank
- **Medium (Free + Some Paid)**: Add Google Safe Browsing, URLScan.io
- **High (Premium)**: Include VirusTotal, IPQualityScore, ThreatFox

See detailed comparison: `docs/performance/provider_comparison.md`

## Roadmap

### ✅ Recently completed

- [x] **Test coverage & property-based tests** - pytest-cov, hypothesis
- [x] **Integration test suite** - HTTP mocks, fixtures
- [x] **Architecture Decision Records** - ADRs for key design decisions
- [x] **Contributing guide** - CONTRIBUTING.md + issue templates
- [x] **Benchmark suite** - pytest-benchmark with throughput/latency tests
- [x] **Memory profiling** - scripts/profile_memory.py
- [x] **Provider comparison** - docs/performance/provider_comparison.md
- [x] **CI/CD** - GitHub Actions for tests, release, PyPI publish

### ✅ Earlier completed

- [x] **Config file** - `.env` support for API keys
- [x] **Webhook notifications** - HMAC-signed webhooks on risk detection
- [x] **DNS/Whois lookup** - `--enrich dns,whois` for domain intel
- [x] **Docker web UI** - REST API + visual frontend with Docker Compose

### 🚧 Future Ideas

- [ ] **Rich terminal output** - Colors and formatting with Rich library
- [ ] **Watch mode** - Monitor URLs periodically (`--watch 1h`)
- [ ] **Quiet mode** - `--quiet` / `--alert-above 50` for scripting
- [ ] **HTML report** - Generate visual report with badges
- [ ] **SSL certificate check** - Validity, expiration, issuer
- [ ] **More enrichment sources** - Screenshot, TLS analysis

Contributions welcome! 🐙

## License

MIT
