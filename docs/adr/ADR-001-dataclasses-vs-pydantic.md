# ADR-001: Dataclasses vs Pydantic for Models

## Status

**Accepted**

## Context

We needed a way to define structured data models for the URL reputation checker that:

1. Provide a stable JSON serialization contract (Schema v1)
2. Are lightweight with minimal dependencies
3. Support Python 3.9+
4. Work well with type hints and IDE autocompletion
5. Allow easy JSON serialization without custom encoders

The two main options considered were:
- **Pydantic**: Popular data validation library with rich features
- **Python dataclasses**: Standard library feature with minimal overhead

## Decision

We chose **Python dataclasses** over Pydantic for the core models.

### Rationale

1. **Zero dependencies**: Dataclasses are part of the standard library (Python 3.7+), keeping the core library lightweight. Pydantic would add a significant dependency.

2. **Simpler serialization**: Using `dataclasses.asdict()` provides straightforward JSON serialization without needing to configure custom encoders or deal with Pydantic's serialization machinery.

3. **Stable output contract**: Our Schema v1 is intentionally simple. We don't need runtime validation on the output models—the validation happens at the provider level.

4. **Frozen semantics**: Using `@dataclass(frozen=True)` ensures immutability, which is valuable for result objects.

5. **Performance**: Dataclasses have lower import overhead and instantiation cost compared to Pydantic models.

### Models Implemented

```python
@dataclass(frozen=True)
class IndicatorV1:
    input: str
    type: IndicatorType
    canonical: str
    domain: Optional[str] = None

@dataclass(frozen=True)
class SourceResultV1:
    name: str
    status: Literal["ok", "error", "skipped"]
    # ...

@dataclass(frozen=True)
class ResultV1:
    schema_version: Literal["1"]
    indicator: IndicatorV1
    verdict: Verdict
    # ...
```

## Consequences

### Positive

- No mandatory dependencies for core functionality
- Fast import and instantiation times
- Simple mental model—standard Python constructs
- Easy to work with typing and static analysis

### Negative

- No built-in runtime validation (intentional trade-off)
- No automatic JSON schema generation
- Manual handling of optional fields with `None` defaults

### Mitigations

- Runtime validation is done at input boundaries (CLI, API) using explicit functions
- JSON schema is documented manually in `docs/schema-v1.md`
- Tests verify serialization round-trips

## Related Decisions

- See ADR-002 for provider registry design
- See `docs/schema-v1.md` for the resulting JSON schema
