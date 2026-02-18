# ADR-003: Cache Storage Strategy (SQLite vs Redis)

## Status

**Accepted**

## Context

We needed a caching mechanism to:

1. Reduce latency for repeated URL checks
2. Minimize API quota usage for providers with rate limits
3. Support offline operation for cached results
4. Be simple to deploy and operate

Options considered:
- **SQLite**: File-based, zero-config, standard library
- **Redis**: In-memory with persistence, requires separate server
- **File-based JSON/CSV**: Simple but no query capabilities

## Decision

We chose **SQLite** as the default cache backend.

### Rationale

1. **Zero dependencies**: SQLite is included in Python's standard library (`sqlite3` module)

2. **Zero configuration**: No server to install, configure, or maintain

3. **Single-user optimized**: The primary use case (CLI tool, library) doesn't require concurrent access from multiple processes

4. **Persistence**: Cache survives process restarts without additional configuration

5. **TTL support**: Implemented at application level with timestamp-based expiration

6. **Portability**: Single `.sqlite` file can be moved, backed up, or deleted easily

### Implementation

```python
@dataclass
class Cache:
    path: str
    
    def get(self, key: str, ttl_seconds: int) -> Optional[dict[str, Any]]:
        # Check timestamp, return None if expired
        ...
    
    def set(self, key: str, value: dict[str, Any]) -> None:
        # UPSERT operation
        ...

# Default location respects XDG_CACHE_HOME
default_cache_path() -> str:
    base = os.getenv("XDG_CACHE_HOME") or os.path.expanduser("~/.cache")
    return os.path.join(base, "url-reputation", "cache.sqlite")
```

### Cache Key Design

Keys are SHA-256 hashes of normalized parameters:
```
key = SHA256("v={schema}|i={canonical}|p={providers}|e={enrichments}")
```

This ensures:
- Cache hits only when all parameters match
- Different enrichment combinations have separate entries
- URL normalization ensures cache consistency

## Consequences

### Positive

- Works out of the box with no setup
- Single file is easy to manage and clear (`rm cache.sqlite`)
- XDG-compliant default location
- Opt-in via CLI (`--cache`)—not enabled by default
- Flexible TTL parsing (`10m`, `24h`, `7d`)

### Negative

- Not suitable for multi-process concurrent writes (SQLite's filesystem locking)
- No built-in memory caching (disk I/O on every operation)
- No distributed caching across machines
- Cache size can grow indefinitely (no eviction policy yet)

### Mitigations

- Cache is opt-in, not required for operation
- `XDG_CACHE_HOME` allows users to control location
- Future work: automatic cache cleanup, size limiting

## Future Considerations

If concurrent/multi-user scenarios become important, we could:

1. Add Redis backend as optional dependency
2. Implement pluggable cache backends
3. Add WAL mode for SQLite for better concurrency

## Usage Examples

```bash
# Use default cache with 24h TTL
url-reputation "https://example.com" --cache --cache-ttl 24h

# Custom cache path
url-reputation "https://example.com" --cache /tmp/urlrep.sqlite --cache-ttl 10m

# No cache (default behavior)
url-reputation "https://example.com"
```

## Related Decisions

- See ADR-001 for why we keep dependencies minimal
- TTL parsing and key generation in `url_reputation/cache.py`
