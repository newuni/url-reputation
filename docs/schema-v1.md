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
      "rate_limit": null
    }
  ],
  "enrichment": {
    "dns": {"a_records": ["93.184.216.34"]}
  }
}
```

## Notes

- `indicator.canonical` is a normalized value used for caching and stable keys.
- `sources[].raw` contains the provider payload as returned by the provider implementation.
- If a provider fails, it should yield a `SourceResultV1` with:
  - `status="error"`
  - `error` filled
  - `raw` may contain partial information.
