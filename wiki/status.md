# url-reputation — Status / Plan (living doc)

> This is a living, transparent roadmap.
>
> Working agreement:
> - We work **task by task**.
> - When a task is completed, we **update this file** (mark done, add notes, link commits).
> - Unblocked tasks should be small enough to finish in one iteration.
> - Prefer backwards-compatible changes; when breaking, document a migration.

## Current snapshot

- Repo: https://github.com/newuni/url-reputation
- Local path on this host: `/root/clawd/skills/url-reputation`
- Latest release: **v1.4.1** (Docker healthcheck + dev workflow)
- Primary focus: **Developer-first unified URL/domain/IP reputation library** (multi-provider “front door”).

## Vision

Provide a single, stable API/CLI that hides the complexity of multiple threat-intel providers (auth, quotas, formats, semantics) and returns a **consistent contract**:

- One input: URL / domain / IP
- One output schema (versioned)
- A unified aggregated verdict + score
- Per-provider results and errors
- Optional enrichment (DNS, WHOIS, redirects, ASN, etc.)
- Good ergonomics for CI (exit codes), logs, and batch processing

## Guiding principles

1. **Stable contract > features**: once the output schema is defined, keep it stable.
2. **Progressive enhancement**: free sources work without keys; paid sources unlock automatically.
3. **Privacy-aware defaults**: avoid submitting full URLs when a host-only lookup is sufficient.
4. **Quota-respecting**: provider-specific rate-limits, retries, backoff.
5. **Composable**: users can pick providers, profiles, cache strategy.

---

## Roadmap (phased)

### Phase 0 — Baseline (done)
- [x] Docker web image healthcheck fix (curl)
- [x] Dev workflow via `Dockerfile.dev` + `pytest`

### Phase 1 — Contract + provider architecture (next)
Goal: define a stable output and refactor to an extensible provider interface.

### Phase 2 — Cache + rate limit + retries
Goal: reduce cost/latency and be safe with quotas.

### Phase 3 — CLI ergonomics + CI integration
Goal: make this a drop-in tool for pipelines.

### Phase 4 — Enrichment & normalization
Goal: better context and fewer false positives.

### Phase 5 — Plugins + ecosystem
Goal: external providers can be added without editing core.

---

## Task board

### Legend
- **Status**: `TODO` | `IN_PROGRESS` | `DONE`
- Each task should include a **Definition of Done** and **Notes**.

### Phase 1 — Contract + provider architecture

#### T1 — Define output schema v1 (URL/domain/IP)
- Status: DONE
- Why: All downstream work (cache, CLI, API) depends on a stable contract.
- Deliverables:
  - `url_reputation/models.py` (pydantic or dataclasses) with `ResultV1` + `SourceResultV1`
  - `schema_version: "1"` present in outputs
  - `ResultV1` includes: `indicator`, `indicator_type`, `canonical`, `verdict`, `risk_score`, `checked_at`, `sources[]`, `enrichment?`, `errors?`
  - A short `docs/schema-v1.md` (examples)
- Definition of Done:
  - CLI `--json` output conforms to the new schema and includes `schema_version`.
  - Tests updated/added.
- Notes:
  - Implemented `ResultV1`/`SourceResultV1` as lightweight dataclasses (no hard pydantic dependency).
  - `check_url_reputation()` now returns Schema v1 keys (`schema_version`, `indicator`, `sources[]`).
  - Backward-compat convenience fields kept: `url`, `domain`.
  - Added docs: `docs/schema-v1.md`.
  - CI: `pytest` passes.

#### T2 — Provider interface + registry
- Status: DONE
- Deliverables:
  - `url_reputation/providers/base.py` with `Provider` interface
  - `url_reputation/providers/registry.py` with registration and selection
  - Move existing sources under providers (wrap existing logic)
- Definition of Done:
  - `check_url_reputation()` uses providers via registry
  - providers can be enabled by name and auto-disabled if missing API key
- Notes:
  - Added `url_reputation/providers/` with Provider interface + Registry.
  - Implemented built-in provider wrappers around existing source modules.
  - `check_url_reputation()` now selects providers through the registry, keeping existing behavior.
  - Tests pass.

#### T3 — Profiles (fast / thorough / privacy / free-only)
- Status: DONE
- Deliverables:
  - `url_reputation/profiles.py`
  - CLI: `--profile fast|thorough|privacy|free`
- Definition of Done:
  - Profiles map to provider sets + timeouts + concurrency
- Notes:
  - Added `url_reputation/profiles.py` with presets: `free`, `fast`, `privacy`, `thorough`.
  - CLI: new flag `--profile` (ignored if `--sources` is provided).
  - Providers that require API keys are still auto-skipped by registry when missing.

### Maintenance / cleanup (rolling)

#### C3 — Static analysis toolchain (ruff + mypy)
- Status: DONE
- Notes:
  - Added Ruff (lint rules) + mypy (type checking) configuration in `pyproject.toml` and docs in `docs/static-analysis.md`.
  - Applied Ruff safe auto-fixes.
  - Ruff status: `ruff check .` passes (we exclude legacy `scripts/**` and ignore E501/E722/B904 initially; tighten later).
  - mypy status: `mypy url_reputation` passes in informational mode (`ignore_errors=true` for initial adoption; tighten later).

#### C0 — Stop tracking build artifacts (dist/)
- Status: DONE
- Notes:
  - Added `dist/` to `.gitignore` and removed old tracked artifacts.

#### C1 — Clean docker-compose.yml (remove obsolete version key)
- Status: DONE
- Notes:
  - Removed compose `version:` header to avoid warnings.

#### C2 — Legacy JSON compatibility switch
- Status: DONE
- Notes:
  - Added `--legacy-json` to include `sources_map` for older consumers.

### Phase 2 — Cache + rate limit + retries

#### T4 — Local cache layer (sqlite)
- Status: DONE
- Deliverables:
  - `url_reputation/cache.py` (sqlite)
  - CLI: `--cache`, `--cache-ttl`, `--no-cache`
  - Cache key based on canonical indicator + provider set + options
- Definition of Done:
  - Demonstrable cache hits; tests for TTL and key stability
- Notes:
  - Implemented sqlite cache in `url_reputation/cache.py`.
  - CLI flags: `--cache [path]`, `--cache-ttl`, `--no-cache`.
  - `check_url_reputation()` supports opt-in caching via `cache_path` + `cache_ttl_seconds`.
  - Added tests in `tests/test_cache.py`.

#### T5 — Provider-specific retries/backoff + concurrency limits
- Status: DONE
- Deliverables:
  - common retry utility with exponential backoff + jitter
  - provider concurrency limits (per provider + global)
  - surface rate-limit metadata in `SourceResultV1.rate_limit?`
- Definition of Done:
  - 429 handling does not spam; respects reset windows when available
- Notes:
  - Added `url_reputation/retry.py` (exponential backoff + jitter).
  - Enforced process-wide + per-provider concurrency using semaphores (useful in batch mode).
  - Providers can set `max_concurrency` and `retry_retries` (configured for built-ins).
  - `SourceResultV1.rate_limit` is now populated when providers implement `parse_rate_limit()`.
  - Tests added for retry helper.

### Phase 3 — CLI ergonomics + CI integration

#### T6 — Exit codes + `--fail-on`
- Status: DONE
- Deliverables:
  - `--fail-on CLEAN|LOW_RISK|MEDIUM_RISK|HIGH_RISK|ERROR`
  - deterministic exit codes for pipelines
- Notes:
  - CLI now exits with:
    - `0` = ok
    - `1` = fail-on threshold reached
    - `2` = verdict ERROR (when fail-on not set) / unexpected error surfaced as ERROR
  - Added tests in `tests/test_exit_codes.py`.

#### T7 — Output formats (pretty/json/ndjson/sarif)
- Status: DONE
- Deliverables:
  - `--format pretty|json|ndjson|sarif`
  - SARIF for GitHub Code Scanning (optional)
- Notes:
  - Added `--format` flag.
  - Implemented minimal SARIF 2.1.0 output.
  - `--json` remains as an alias for `--format json`.

#### T8 — Batch streaming + large files
- Status: DONE
- Deliverables:
  - `--file` supports large lists efficiently
  - NDJSON streaming mode; progress summaries
- Notes:
  - Added `iter_urls_from_file()` + `run_batch()` that stream input and bound in-flight tasks.
  - Added NDJSON output mode for streaming consumption.

### Phase 4 — Enrichment & normalization

#### T9 — Canonicalization and indicator typing
- Status: TODO
- Deliverables:
  - Canonical URL normalization + IDN/punycode
  - Determine `indicator_type` reliably

#### T10 — Enrichment plugins (dns/whois/redirects/asn)
- Status: TODO
- Deliverables:
  - Enrichment interface similar to providers
  - Optional based on flags: `--enrich dns,whois,redirects,asn`

### Phase 5 — Plugins + ecosystem

#### T11 — Entry points for external providers
- Status: TODO
- Deliverables:
  - `pyproject.toml` entrypoints
  - docs: how to publish a provider package

---

## Next task to execute

**T9 — Canonicalization and indicator typing**

When you tell me “sigue”, I will:
1) implement T6,
2) run tests,
3) commit + push,
4) update this file (mark T2 DONE, add commit refs + notes),
5) then stop and wait for your next instruction.
