# Plugins (providers & enrichers)

`url-reputation` supports third-party extensions via Python entry points.

## Provider plugins

In your package `pyproject.toml`:

```toml
[project.entry-points."url_reputation.providers"]
my_provider = "mypkg.providers:provider"
```

Where `mypkg.providers:provider` is either:
- a **Provider instance**, or
- a **factory** returning a Provider instance.

The Provider must implement the `url_reputation.providers.base.Provider` interface.

## Enricher plugins

```toml
[project.entry-points."url_reputation.enrichers"]
my_enricher = "mypkg.enrichers:enricher"
```

(Enricher loading will be wired similarly when we expand enrichment plugins.)
