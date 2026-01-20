# URL Reputation Checker

Multi-source URL/domain security analysis with aggregated risk scoring.

## Features

- **10 reputation sources**: VirusTotal, URLScan.io, Google Safe Browsing, AbuseIPDB, URLhaus, PhishTank/OpenPhish, DNSBL, AlienVault OTX, IPQualityScore, ThreatFox
- **Works without API keys**: Free sources (URLhaus, OpenPhish, DNSBL, AlienVault OTX) always available
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
```

### Check specific sources only

```bash
url-reputation "https://example.com" --sources urlhaus,dnsbl
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
python3 -m unittest discover tests/

# Run specific test file
python3 -m unittest tests.test_checker

# With pytest (if installed)
pytest tests/ -v
```

## Roadmap

Upcoming features:

- [x] **Config file** - `.env` support for API keys ✅
- [ ] **Rich terminal output** - Colors and formatting with Rich library
- [ ] **Watch mode** - Monitor URLs periodically (`--watch 1h`)
- [x] **Webhook notifications** - HMAC-signed webhooks on risk detection ✅
- [ ] **Quiet mode** - `--quiet` / `--alert-above 50` for scripting
- [ ] **HTML report** - Generate visual report with badges
- [ ] **Whois lookup** - Domain age, registrant info
- [ ] **SSL certificate check** - Validity, expiration, issuer
- [ ] **API server mode** - `--serve` for local REST API
- [ ] **GitHub Action** - Scan URLs in PRs/commits

Contributions welcome! 🐙

## License

MIT
