# URL Reputation API Reference

## Public API

### `check_url_reputation()`

Main function to check URL/domain/IP reputation.

```python
from url_reputation import check_url_reputation

result = await check_url_reputation(
    "https://example.com",
    providers=["urlhaus", "dnsbl"],  # Optional: specific providers
    cache_path="/tmp/cache.sqlite",  # Optional: enable caching
    cache_ttl=3600,                   # Optional: TTL in seconds
)
```

**Parameters:**
- `indicator` (str): URL, domain, or IP to check
- `providers` (list[str] | None): Provider names to use (None = all available)
- `timeout` (float): Request timeout in seconds
- `cache_path` (str | None): Path to SQLite cache (None = no cache)
- `cache_ttl` (int): Cache TTL in seconds
- `enrich` (list[str]): Enrichment modules to run (dns, whois, redirects, asn)

**Returns:** `ResultV1`

```python
{
    "schema_version": "1",
    "indicator": {
        "input": "https://example.com",
        "type": "url",
        "canonical": "https://example.com",
        "domain": "example.com"
    },
    "verdict": "CLEAN",  # CLEAN | LOW_RISK | MEDIUM_RISK | HIGH_RISK | ERROR
    "risk_score": 0,     # 0-100
    "sources": [...],    # Per-provider results
    "enrichment": {...}, # Optional enrichment data
    "checked_at": "2024-01-15T10:30:00",
}
```

### `check_urls_batch()`

Batch process multiple URLs efficiently.

```python
from url_reputation import check_urls_batch

results = await check_urls_batch(
    ["https://a.com", "https://b.com"],
    max_concurrent=10,
)
```

### `get_profile()`

Get predefined provider profiles.

```python
from url_reputation.profiles import get_profile

providers = get_profile("fast")  # fast | thorough | free | privacy
```

## Data Models

### `ResultV1`

Top-level result structure.

| Field | Type | Description |
|-------|------|-------------|
| `schema_version` | str | Always "1" |
| `indicator` | IndicatorV1 | Input metadata |
| `verdict` | str | Aggregated verdict |
| `risk_score` | int | 0-100 risk score |
| `sources` | list[SourceResultV1] | Per-provider results |
| `enrichment` | dict | Optional enrichment data |
| `checked_at` | str | ISO timestamp |
| `errors` | list | Any errors encountered |

### `SourceResultV1`

Individual provider result.

| Field | Type | Description |
|-------|------|-------------|
| `name` | str | Provider name |
| `status` | str | "ok" | "error" | "skipped" |
| `listed` | bool | Whether indicator is flagged |
| `confidence` | float | 0.0-1.0 confidence |
| `details` | dict | Provider-specific results |
| `checked_at` | str | ISO timestamp |

## Providers

### Built-in Providers

- `urlhaus` - Malware URLs (no API key)
- `dnsbl` - DNS blocklists (no API key)
- `phishtank` - Phishing database (no API key)
- `otx` - AlienVault OTX (optional API key)
- `virustotal` - Multi-engine (API key required)
- `urlscan` - Website scanning (API key required)
- `google_safebrowsing` - Google API (API key required)

## CLI Reference

See `url-reputation --help` for complete CLI documentation.

Common commands:

```bash
# Single URL
url-reputation "https://example.com"

# JSON output
url-reputation "https://example.com" --json

# Specific providers
url-reputation "https://example.com" --sources urlhaus,dnsbl

# With enrichment
url-reputation "https://example.com" --enrich dns,whois

# Batch from file
url-reputation --file urls.txt --format json

# Fail on threshold (for CI)
url-reputation --file urls.txt --fail-on MEDIUM_RISK
```
