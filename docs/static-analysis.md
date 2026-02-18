# Static analysis

We use the most common modern Python combo:

- **Ruff** for linting (and optional formatting)
- **mypy** for type checking

## Run locally (recommended via dev container)

```bash
cd /root/clawd/skills/url-reputation

docker build -t url-reputation-dev -f web/Dockerfile.dev .

docker run --rm url-reputation-dev ruff check .
docker run --rm url-reputation-dev mypy url_reputation
```

## Notes

- We keep the configuration in `pyproject.toml`.
- The mypy baseline is enforced (no global `ignore_errors=true`).
- Start strictness low, then tighten gradually as we add types.
