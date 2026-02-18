# ADR-002: Provider Registry Design (Plugin Pattern)

## Status

**Accepted**

## Context

We needed an extensible architecture for integrating multiple reputation sources (VirusTotal, URLhaus, PhishTank, etc.) that:

1. Allows built-in providers to be registered automatically
2. Supports third-party provider packages via entry points
3. Provides a consistent interface for checking URL reputation
4. Enables runtime selection of providers based on availability

## Decision

We implemented a **plugin-based provider registry** using Python entry points (`importlib.metadata`).

### Architecture

```
┌─────────────────────────────────────────────────────────┐
│                    Registry                             │
├─────────────────────────────────────────────────────────┤
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────────┐ │
│  │  urlhaus    │  │  phishtank  │  │   virustotal    │ │
│  │  (builtin)  │  │  (builtin)  │  │   (builtin)     │ │
│  └─────────────┘  └─────────────┘  └─────────────────┘ │
│                                                         │
│  ┌─────────────────────────────────────────────────┐   │
│  │  Entry Points: url_reputation.providers         │   │
│  │  (allows third-party packages to register)      │   │
│  └─────────────────────────────────────────────────┘   │
└─────────────────────────────────────────────────────────┘
```

### Key Components

1. **Base Provider Class** (`url_reputation/providers/base.py`):
   ```python
   class Provider(ABC):
       name: str
       
       @abstractmethod
       def is_available(self) -> bool: ...
       
       @abstractmethod
       async def check(self, indicator: str) -> dict[str, Any]: ...
   ```

2. **Registry** (`url_reputation/providers/registry.py`):
   - Loads built-in providers
   - Discovers third-party providers via entry points
   - Provides selection/filtering by availability

3. **Entry Point Group**: `url_reputation.providers`

### Provider Loading

```python
# Built-in providers are auto-registered
from url_reputation.providers.builtins import registry

# Third-party packages can register via setup.py/pyproject.toml:
[project.entry-points."url_reputation.providers"]
my_provider = "my_package.providers:my_provider_instance"
```

## Consequences

### Positive

- **Extensibility**: Third parties can add providers without modifying core code
- **Lazy loading**: Providers are imported only when needed
- **Type safety**: Abstract base class enforces consistent interface
- **Testability**: Easy to mock providers in tests

### Negative

- Entry point discovery overhead at registry initialization
- Entry points can fail to load silently (handled with try/except)
- Plugin ecosystem requires documentation for discoverability

### Mitigations

- Registry logs load failures for debugging
- Built-in providers are always available
- Clear documentation for plugin authors (`docs/plugins.md`)

## Example: Adding a Custom Provider

```python
# my_package/custom_provider.py
from url_reputation.providers.base import Provider

class CustomProvider(Provider):
    name = "custom"
    
    def is_available(self) -> bool:
        return True
    
    async def check(self, indicator: str) -> dict[str, Any]:
        return {"listed": False, "details": {}}

# Entry point in pyproject.toml
[project.entry-points."url_reputation.providers"]
custom = "my_package.custom_provider:CustomProvider"
```

## Related Decisions

- See ADR-003 for cache storage strategy
- See `docs/plugins.md` for detailed plugin development guide
