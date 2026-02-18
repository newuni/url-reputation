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

Where `mypkg.enrichers:enricher` is either:
- an **Enricher instance**, or
- a **factory** returning an Enricher instance.

The Enricher must implement the `url_reputation.enrichment.base.Enricher` interface.

Enricher entry points are loaded automatically (best-effort) into the enrichment registry.
