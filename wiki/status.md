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
- Latest release: **v1.6.0** (Polish phase: tests, docs, performance, CI/CD)
- Previous release: v1.5.0 (T13-T19 improvements)
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
  - mypy status: `mypy url_reputation` baseline is enforced (no global `ignore_errors=true`; tighten options gradually).

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
- Status: DONE
- Deliverables:
  - Canonical URL normalization + IDN/punycode
  - Determine `indicator_type` reliably
- Notes:
  - Added `url_reputation/normalize.py` and updated `canonicalize_indicator()` to use it.
  - Canonicalization includes: scheme/lowercase host, IDNA punycode, fragment removal, default port stripping.

#### T10 — Enrichment plugins (dns/whois/redirects/asn)
- Status: DONE
- Deliverables:
  - Enrichment interface similar to providers
  - Optional based on flags: `--enrich dns,whois,redirects,asn`
- Notes:
  - Added `url_reputation/enrichment/` with Enricher interface + registry.
  - Implemented built-in enrichers for `dns` and `whois`.
  - CLI now uses `enrich_domain()`.

### Phase 5 — Plugins + ecosystem

#### T11 — Entry points for external providers
- Status: DONE
- Deliverables:
  - `pyproject.toml` entrypoints
  - docs: how to publish a provider package
- Notes:
  - Added entrypoint groups in `pyproject.toml` and loader in `Registry.load_entrypoints()`.
  - Documented in `docs/plugins.md`.

---

## Backlog (new tasks)

### Phase 2 — Cache + rate limit + retries (improvements)

#### T12 — Redirect-chain enricher (URL-based)
- Status: DONE
- Why: redirects are a strong phishing signal and help analysts understand the *final* destination.
- Deliverables:
  - Enricher: `redirects`
  - Output: `final_url`, `chain[]`, `hops`
  - Limits: `max_hops`, timeouts; avoid downloading bodies where possible
- Definition of Done:
  - `--enrich redirects` works in single-URL mode (uses canonical indicator)
  - Tests cover basic shape + non-URL skip
  - Docs updated (`docs/schema-v1.md` / enrichment docs)
- Notes:
  - Commit: `1d247d7` — feat: redirects enricher + typed enrichment context
  - Enrichment framework now supports indicator types (url/domain/ip) so URL-based enrichers can exist.
  - Added built-in enricher: `redirects` (URL redirect chain + final URL).
  - Added tests and made DNS enrichment tests deterministic when dnspython is installed.

#### T13 — Provider-specific rate limit parsing (real)
- Status: DONE
- Deliverables:
  - For each built-in provider, parse rate-limit headers/fields into `SourceResultV1.rate_limit`
  - Retry policy respects `Retry-After` and reset windows when available
- Notes:
  - Added normalized `RateLimitInfo` parsing from provider response headers (GitHub-style `X-RateLimit-*`, generic `Retry-After`).
  - Built-in HTTP sources now attach response metadata under `_http` so providers can parse headers without network in tests.
  - Output now includes `sources[].rate_limit_info` (rich, JSON-safe), while keeping `sources[].rate_limit` for backwards compatibility.

### Phase 3 — CLI ergonomics + CI integration (improvements)

#### T14 — Report outputs (markdown + summary)
- Status: DONE
- Deliverables:
  - `--format markdown` (single + batch)
  - A one-page summary at end of batch runs (worst verdict, counts by verdict, errors)
- Notes:
  - Commit: `2c45aa0` (feat: markdown report output + batch summary (T14))

#### T15 — Batch mode: budget + deterministic ordering option
- Status: DONE
- Deliverables:
  - `--budget-seconds` and/or `--max-requests` to cap work in CI
  - `--preserve-order` (optional): yield results in input order (buffered)
- Notes:
  - Commit: `98edd6f` — feat: batch budgeting + preserve-order (T15)

### Phase 4 — Enrichment & normalization (more)

#### T16 — ASN/Geo enricher (domain/ip)
- Status: DONE
- Deliverables:
  - `--enrich asn_geo` (alias: `asn`) mapping domain/IP→ASN/org/prefix + basic geo
  - Online-first, no API keys; local/offline fallback with quality reporting
  - Deterministic offline tests (no external network)
- Notes:
  - Added `url_reputation/enrichment/asn_geo.py` (RIPEstat + Team Cymru + ip-api, with TTL caching and graceful fallback).
  - Output includes a `quality` object: source/confidence/coverage/notes/sources.
  - Registered enricher in `url_reputation/enrichment/builtins.py` as `asn_geo` and alias `asn`.
  - Docs updated: `docs/schema-v1.md`.
  - Commit: `9cb0a4b` (feat: asn/geo enricher with quality report (T16))

### Phase 5 — Plugins + ecosystem (improvements)

#### T17 — Enricher entrypoints loader + docs
- Status: DONE
- Deliverables:
  - Mirror provider entrypoints: load enrichers from `url_reputation.enrichers`
  - Docs + minimal example package
- Notes:
  - Added `EnrichmentRegistry.load_entrypoints()` (best-effort) + `list_names()`.
  - Updated `docs/plugins.md` with enricher entrypoint usage.
  - Commit: `f820e78` (feat: enricher entrypoints loader (T17))

### Maintenance / tightening

#### T18 — Tighten mypy (progressively)
- Status: DONE
- Deliverables:
  - Move from informational to enforceable mypy (reduce `ignore_errors=true`)
  - Fix highest-value type issues first (core library surface)
- Notes:
  - Removed global `ignore_errors=true` and tightened types in core surfaces (checker/CLI/providers).
  - Eliminated legacy `type: ignore[...]` markers by fixing underlying typing.
  - Commit: `ea420cb` (chore: tighten mypy baseline (T18))

#### T19 — Unified aggregated scoring rules (explainable)
- Status: DONE
- Deliverables:
  - `risk_score` explanation (`score_breakdown` / `reasons[]`)
  - Configurable weights per provider and a small set of rules (redirects + domain age, etc.)
- Commit: `4545fc8` (feat: explainable aggregated scoring (T19))

---

### Phase 6 — Polish / Quality / Performance

#### P1 — Test coverage analysis & gaps
- **Status:** DONE
- **Assigned to:** Agent Testing
- **Deliverables:**
  - Integrar `pytest-cov` en `pyproject.toml`
  - Generar reporte HTML de cobertura
  - Identificar zonas sin cobertura (target: >90%)
  - Tests para edge cases (input vacío, URLs malformadas, timeouts de red)
- **DoD:** `pytest --cov` pasa + informe de gaps publicado

#### P2 — Property-based tests
- **Status:** DONE
- **Assigned to:** Agent Testing
- **Deliverables:**
  - Añadir `hypothesis` como dependencia de test
  - Tests properties para `normalize.py` (URLs arbitrarias → siempre retornan canonical válido)
  - Tests properties para scoring (score entre 0-100, monotonicidad con más fuentes positivas)
- **DoD:** Tests properties ejecutan en CI sin fallos

#### P3 — Integration tests end-to-end
- **Status:** DONE
- **Assigned to:** Agent Testing
- **Deliverables:**
  - Suite `test_integration.py` con mocks de HTTP (responses/httpx)
  - Escenarios: timeout total, provider caído, combinación de fuentes libres
  - Fixture compartido con caché en memoria para tests rápidos
- **DoD:** Tests corren en <30s, no hacen requests reales

### Phase 7 — Documentation

#### P4 — Architecture Decision Records (ADRs)
- **Status:** DONE
- **Assigned to:** Agent Documentation
- **Deliverables:**
  - Carpeta `docs/adr/`
  - ADR-001: Por qué dataclasses vs Pydantic
  - ADR-002: Diseño del provider registry
  - ADR-003: Estrategia de caché (sqlite vs redis)
- **DoD:** 3+ ADRs escritos, enlazados desde README

#### P5 — Contributing guide
- **Status:** DONE
- **Assigned to:** Agent Documentation
- **Deliverables:**
  - `CONTRIBUTING.md` (setup dev, run tests, convenciones de commits)
  - Issue templates (bug report, feature request)
  - Checklist de PR (tests pasan, ruff/mypy verdes)
- **DoD:** PR de ejemplo sigue el flujo documentado

#### P6 — API reference auto-generada
- **Status:** DONE
- **Assigned to:** Agent Documentation
- **Deliverables:**
  - Docs de API pública (`check_url_reputation`, `ResultV1`, providers)
  - Generador con `pdoc` o `mkdocstrings`
  - Publicación en GitHub Pages (opcional)
- **DoD:** Docs generadas automáticamente en CI

### Phase 8 — Benchmarks & Performance

#### P7 — Benchmark suite
- **Status:** DONE
- **Assigned to:** Agent Performance
- **Deliverables:**
  - `tests/bench/` con `pytest-benchmark`
  - Benchmarks: throughput URLs/segundo, latencia percentil p95/p99
  - Comparativa: profile `fast` vs `thorough` vs `free`
- **DoD:** Gráfico de rendimiento en README
- **Notes:**
  - Created `tests/bench/test_benchmark.py` with comprehensive benchmarks
  - Created `scripts/run_benchmarks.py` with CSV and chart generation
  - Added performance section to README.md with comparison tables

#### P8 — Memory profiling
- **Status:** DONE
- **Assigned to:** Agent Performance
- **Deliverables:**
  - Script `scripts/profile_memory.py` con `memory_profiler`
   - Medición de uso RAM en modo batch (1000 URLs)
  - Identificación de fugas (caché, sesiones HTTP)
- **DoD:** Reporte de memoria publicado, mejoras aplicadas si >100MB/1k URLs
- **Notes:**
  - Created `scripts/profile_memory.py` with tracemalloc profiling
  - Generates report at `docs/performance/memory_report.md`
  - Tests show expected memory usage well under 100MB/1k URLs threshold

#### P9 — Comparativa de providers (latencia/costes)
- **Status:** DONE
- **Assigned to:** Agent Performance
- **Deliverables:**
  - Notebook/script que benchmarkea cada provider real
  - Tabla: latencia media, rate limits, precio por 1k queries
  - Recomendaciones de "presupuesto" (bajo/medio/alto)
- **DoD:** Docs actualizados con tabla comparativa
- **Notes:**
  - Created `scripts/benchmark_providers.py` for provider comparison
  - Generates markdown report at `docs/performance/provider_comparison.md`
  - Added provider comparison table to README.md
  - Included budget recommendations (low/medium/high)

### Phase 9 — Tooling & Automation

#### P10 — Release automation (GitHub Actions)
- **Status:** DONE
- **Assigned to:** Agent Performance
- **Deliverables:**
  - Workflow que corre tests + ruff + mypy en push
  - Workflow de release: tag → PyPI + GitHub Release con changelog
  - Test en múltiples Python (3.10, 3.11, 3.12)
- **DoD:** Release v1.6.0 publicada vía CI con un click
- **Notes:**
  - Created `.github/workflows/ci.yml` with matrix testing (Python 3.10, 3.11, 3.12)
  - Created `.github/workflows/release.yml` with PyPI publishing and GitHub Releases
  - CI runs tests, ruff, mypy on push and PR
  - Release triggers on v* tags

---

## Execution Mode

**Swarm Mode ACTIVE**: 3 agents trabajando en paralelo sobre P1-P10.

### Agent Assignments
- **Agent Testing** → P1, P2, P3 (Fase 6: Testing)
- **Agent Documentation** → P4, P5, P6 (Fase 7: Docs)
- **Agent Performance** → P7, P8, P9, P10 (Fases 8-9: Performance + Automation)

### Constraints
- Todos los cambios deben pasar: `pytest`, `ruff check .`, `mypy url_reputation`
- Actualizar este archivo (wiki/status.md) tras cada tarea completada
- Commits atómicos con mensajes descriptivos
- Version bump a v1.6.0 al finalizar

---

## Release v1.6.0 Summary

**Phase 6-9 (Polish) COMPLETED**

All P1-P10 tasks implemented by swarm of 3 agents:

| Agent | Tasks | Status |
|-------|-------|--------|
| Testing Agent | P1, P2, P3 | ✅ Committed (coverage, property tests, integration) |
| Documentation Agent | P4, P5, P6 | ✅ Committed (ADRs, CONTRIBUTING.md, issue templates) |
| Performance Agent | P7, P8, P9, P10 | ✅ Committed (benchmarks, profiling, CI workflows) |

**Key changes in v1.6.0:**
- 146 total tests (133 core + 13 benchmarks)
- Property-based tests with `hypothesis`
- 3 ADRs documenting architecture decisions
- Complete CI/CD via GitHub Actions
- Performance benchmarking suite

**Commits:**
- `c75f502` — feat(docs,tests): complete P1-P6 polish phase
- `2462a2b` — perf(P7): add benchmark suite with pytest-benchmark
- `dcc3fcf` — chore(release): bump version to 1.6.0

---

## Phase 10 — Static Analysis Hardening (incremental)

Execution strategy agreed with owner: **blocks of 2** tasks.

### Block A (done)

#### Q1 — mypy: enable `check_untyped_defs`
- **Status:** DONE
- **Deliverables:**
  - `check_untyped_defs = true` in `pyproject.toml`
  - Type fixes in CLI typing flow (`IndicatorType` + mapped source payload typing)
- **DoD:** `mypy url_reputation` green

#### Q2 — mypy: enable `warn_return_any`
- **Status:** DONE
- **Deliverables:**
  - `warn_return_any = true` in `pyproject.toml`
  - Harden return typing in cache/provider/enricher wrappers and JSON decode paths
- **DoD:** `mypy url_reputation` green

### Block B (done)

#### Q3 — Ruff: stop ignoring `E722` (bare except)
- **Status:** DONE
- **Deliverables:**
  - Remove `E722` from ignore list
  - Replace `except:` with `except Exception:` in legacy modules
- **DoD:** `ruff check .` green with `E722` enforced

#### Q4 — Ruff: stop ignoring `B904` (exception chaining)
- **Status:** DONE
- **Deliverables:**
  - Remove `B904` from ignore list
  - Add explicit chaining (`raise ... from e`) where needed
- **DoD:** `ruff check .` green with `B904` enforced

### Block C (done)

#### Q5 — mypy: enable `disallow_untyped_defs`
- **Status:** DONE
- **Deliverables:**
  - `disallow_untyped_defs = true` in `pyproject.toml`
  - Add explicit annotations to remaining untyped defs in CLI and enrichers
- **DoD:** `mypy url_reputation` green

#### Q6 — mypy: enable `strict_equality`
- **Status:** DONE
- **Deliverables:**
  - `strict_equality = true` in `pyproject.toml`
  - Keep runtime behavior unchanged while satisfying stricter checks
- **DoD:** `mypy url_reputation` green with strict equality enabled

### Validation (after Q1-Q6)
- `ruff check .` ✅
- `mypy url_reputation` ✅
- `pytest tests/` ✅ (146 passed)

### Commits
- `16124a2` — chore(quality): tighten mypy + ruff levels (steps 1-4)
- `de8e072` — chore(quality): enable mypy disallow_untyped_defs + strict_equality

---

### Block D (done)

#### Q7 — Ruff: adopt `UP` family (pyupgrade), incremental baseline
- **Status:** DONE
- **Deliverables:**
  - Added `UP` to Ruff `select`
  - Auto-applied safe fixes and kept noisy migration rule (`UP045`) deferred for phased adoption
- **DoD:** `ruff check .` green with `UP` enabled in baseline

#### Q8 — Ruff: adopt `SIM` family (simplify), incremental baseline
- **Status:** DONE
- **Deliverables:**
  - Added `SIM` to Ruff `select`
  - Applied safe simplifications and kept style-only/high-noise SIM rules deferred for now
- **DoD:** `ruff check .` green with `SIM` enabled in baseline

## Next task to execute

**COMPLETED** — Q1-Q8 done in blocks of 2.

Future hardening (optional):
- Tighten deferred `UP/SIM` codes gradually (`UP045`, `SIM105`, `SIM108`, `SIM113`, `SIM117`)
- Add Ruff families `RET`, `C4`
- Enforce coverage floor in CI (`--cov-fail-under` progressive)

### Block E (done)

#### Q9 — Resolve deferred `SIM117` (nested `with`) + `SIM113` (enumerate)
- **Status:** DONE
- **Deliverables:**
  - Consolidated nested `with` contexts in tests and checker internals
  - Refactored batch loop index handling to `enumerate()`
- **DoD:** `ruff check .` green without ignoring `SIM117` / `SIM113`

#### Q10 — Resolve deferred `SIM108` (ternary preference)
- **Status:** DONE
- **Deliverables:**
  - Rewrote style-only `if/else` assignments in markdown/scoring
- **DoD:** `ruff check .` green without ignoring `SIM108`

### Deferred-by-design (explicitly parked)

The following rules remain intentionally deferred to avoid high-noise diffs:
- `UP045` (`Optional[T]` → `T | None` mass migration)
- `SIM105` (replace `try/except/pass` with `contextlib.suppress`)

Decision: resolve these incrementally in dedicated small blocks, updating this status doc after each block.
