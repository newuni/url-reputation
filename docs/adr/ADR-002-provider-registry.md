# ADR-002: Provider Registry Design

## Status

**Accepted**

## Context

We needed a flexible, extensible way to manage multiple reputation providers (URLhaus, VirusTotal, etc.) that:

1. Allows adding new providers without modifying core code
2. Supports both built-in and external (plugin) providers
3. Handles provider availability (API keys, network)
4. Enables profile-based provider selection (fast, thorough, free)
5. Provides consistent interface across all providers

## Decision

We implemented a **Provider Registry pattern** with entry points for plugins.

### Architecture

```python
# Base interface
class Provider(ABC):
    name: str
    max_concurrency: int = 5
    
    @abstractmethod
    def is_available(self) -> bool:
        """Check if provider can be used (has API key, etc.)"""
        
    @abstractmethod
    async def check(self, indicator: str, ...) -> dict:
        """Perform the check"""

# Registry
class ProviderRegistry:
    def register(self, provider: Provider) -> None: ...
    def get_providers(self, names: list[str] | None = None) -> list[Provider]: ...
    def load_entrypoints(self) -> None: ...  # Load external providers
```

### Key Design Choices

1. **Abstract Base Class**: All providers inherit from `Provider`, ensuring consistent interface
2. **Entry Points**: External packages register via `pyproject.toml` `[project.entry-points."url_reputation.providers"]`
3. **Auto-discovery**: Built-in providers auto-register on import
4. **Availability Check**: `is_available()` allows runtime filtering (e.g., skip providers without API keys)
5. **Concurrency Control**: Each provider declares `max_concurrency` for rate limiting

## Consequences

### Positive

- **Extensibility**: New providers added without touching core code
- **Testability**: Easy to mock providers in tests
- **Flexibility**: Users pick providers via `--sources` or `--profile`
- **Plugin Ecosystem**: Third parties can publish providers independently

### Negative

- **Import-time Registration**: Providers register on module import (could slow startup)
- **Global State**: Registry is singleton (potential for conflicts in unusual use cases)
- **Entry Point Overhead**: Scanning entry points adds ~10-50ms to startup

### Mitigations

- Lazy loading of provider modules
- Registry can be instantiated per-check if needed
- Entry point loading is opt-in via `load_entrypoints()`

## Related Decisions

- See ADR-001 for model design
- See ADR-003 for caching strategy
- See `docs/plugins.md` for plugin implementation guide
