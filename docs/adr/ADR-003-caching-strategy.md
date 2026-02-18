# ADR-003: Caching Strategy

## Status

**Accepted**

## Context

URL reputation checks involve:
- Network I/O (slow, variable latency)
- Rate-limited APIs
- Repeated queries for same URLs

We needed a caching strategy that:
1. Reduces API calls (cost, rate limits)
2. Improves response time for repeated queries
3. Handles TTL (time-to-live) per cached result
4. Works without external dependencies
5. Is optional and transparent

## Decision

We chose **SQLite-based local cache** as the primary caching mechanism.

### Architecture

```python
class SqliteCache:
    def __init__(self, path: str | None = None):
        # In-memory if path is None, file-backed otherwise
        
    def get(self, key: str) -> dict | None:
        # Return cached result or None
        
    def set(self, key: str, value: dict, ttl: int) -> None:
        # Store with expiration timestamp
        
    def cleanup(self) -> None:
        # Remove expired entries
```

### Key Design Choices

1. **SQLite**: 
   - Zero external dependencies (stdlib sqlite3)
   - ACID guarantees
   - Persistent across process restarts
   - Queryable for debugging

2. **Cache Key Strategy**:
   ```
   key = hash(normalized_indicator + provider_set_hash + options_hash)
   ```
   - Changes to provider set invalidate cache
   - Options (like `--enrich`) affect key

3. **TTL per Entry**:
   - Configurable per check
   - Stored as expiration timestamp
   - Background cleanup on access

4. **Opt-in**:
   - CLI: `--cache [path]` or `--no-cache`
   - API: `cache_path` parameter
   - Default: disabled (predictable behavior)

### Alternatives Considered

| Option | Pros | Cons | Decision |
|--------|------|------|----------|
| SQLite | Stdlib, persistent, queryable | Single-node | **Chosen** |
| Redis | Multi-node, fast | External dependency | Not now |
| In-memory dict | Fastest, simplest | Lost on restart, no memory limits | Used for tests |
| DiskCache (third-party) | Pythonic API | Extra dependency | Not needed |

## Consequences

### Positive

- **Zero deps**: Works out of the box
- **Predictable**: SQLite is battle-tested
- **Observable**: Can inspect cache file directly
- **Flexible**: In-memory for tests, file-backed for production

### Negative

- **Single-node**: No distributed caching
- **Concurrency**: SQLite handles it but has limits
- **Cache invalidation**: Manual strategy only

### Future

- Distributed cache (Redis) for high-throughput deployments
- Cache warming/pre-fetching
- Smart invalidation based on provider semantics

## Related Decisions

- See ADR-001 for models (cache stores ResultV1)
- See ADR-002 for provider registry (cache key includes provider set)
