# Schema v1 (ResultV1)

All JSON outputs **must** include `schema_version: "1"`.

Note: the CLI also supports presentation formats (`--format pretty|markdown`) which are derived from Schema v1 results but are not themselves schema-validated.

## Top-level

```json
{
  "schema_version": "1",
  "indicator": {
    "input": "https://example.com/path?q=1",
    "type": "url",
    "canonical": "https://example.com/path?q=1",
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
      "listed": false,
      "score": null,
      "raw": {"listed": false},
      "error": null,
      "rate_limit": null,
      "rate_limit_info": null
    }
  ],
  "enrichment": {
    "dns": {"a_records": ["93.184.216.34"]},
    "asn_geo": {
      "ips": ["93.184.216.34"],
      "asn": {"number": 15169, "name": null, "org": "Google LLC", "prefix": "93.184.216.0/24"},
      "geo": {"country": "United States", "region": "California", "city": "Los Angeles", "lat": 34.05, "lon": -118.24, "isp": "Example ISP"},
      "quality": {
        "source": "online",
        "confidence": "high",
        "coverage": ["ips", "asn", "org", "prefix", "country", "region", "city", "latlon", "isp"],
        "notes": [],
        "sources": ["ip-api", "ripe"]
      }
    },
    "redirects": {
      "final_url": "https://www.example.com/",
      "hops": 1,
      "chain": [
        {"url": "http://example.com", "status": 301, "location": "https://www.example.com/"},
        {"url": "https://www.example.com/", "status": 200, "location": null}
      ]
    }
  }
}
```

## Notes

- `indicator.canonical` is a normalized value used for caching and stable keys.
- `sources[].raw` contains the provider payload as returned by the provider implementation.
- `sources[].rate_limit` is a small backwards-compatible subset (limit/remaining/reset_at).
- `sources[].rate_limit_info` is richer metadata when available (retry-after, reset window, raw headers).
- `score_breakdown` is a list of explainable scoring contributions. Each entry has:
  - `rule_id`: stable rule identifier
  - `provider`: provider/enrichment name (e.g., `phishtank`, `redirects`, `whois`)
  - `points`: base points for the rule
  - `weight`: configured weight for that provider
  - `weighted_points`: points after weights (rounded half-up)
  - `reason`: short description
  - `evidence`: small JSON-safe dict to support the reason
- `reasons` is a human-readable list derived from `score_breakdown`.
- Provider/enrichment weights are configurable via `URL_REPUTATION_PROVIDER_WEIGHTS` (JSON map of name→float).
- If a provider fails, it should yield a `SourceResultV1` with:
  - `status="error"`
  - `error` filled
  - `raw` may contain partial information.
