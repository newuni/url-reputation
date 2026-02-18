# Schema v1 (ResultV1)

All JSON outputs **must** include `schema_version: "1"`.

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
- If a provider fails, it should yield a `SourceResultV1` with:
  - `status="error"`
  - `error` filled
  - `raw` may contain partial information.
