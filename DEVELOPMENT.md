# Development (url-reputation)

Repo path on this host: `/root/clawd/skills/url-reputation`

## Option A — Dev via Docker (recommended)

### Build dev image

```bash
cd /root/clawd/skills/url-reputation

docker build -t url-reputation-dev -f web/Dockerfile.dev .
```

### Run tests (inside container)

```bash
docker run --rm url-reputation-dev pytest -q
```

### Run API locally (inside container)

```bash
docker run --rm -p 8095:8000 url-reputation-dev
# health: http://127.0.0.1:8095/api/health
```

## Option B — Local venv

```bash
cd /root/clawd/skills/url-reputation
python3 -m venv .venv
source .venv/bin/activate
pip install -U pip
pip install -e ".[dev]"
pytest -q
```

## Notes
- `docker-compose.yml` is meant for the web UI/API and includes a healthcheck.
- The production `web/Dockerfile` now installs `curl` so the compose healthcheck works.
