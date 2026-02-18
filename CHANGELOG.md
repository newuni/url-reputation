# Changelog

All notable changes to this project are documented here.

## [v1.7.0] - 2026-02-18
### Changed
- Significant static-analysis hardening completed in staged blocks.
- mypy tightened (`no_implicit_optional`, `check_untyped_defs`, `warn_return_any`, `disallow_untyped_defs`, `strict_equality`).
- Ruff tightened and adopted additional rule families (`UP`, `SIM`) with deferred items fully resolved.
- Test and codebase cleanups to keep `ruff`, `mypy`, and full test suite green under stricter rules.

## [v1.6.0] - 2026-02-18
### Added
- Benchmark suite (`pytest-benchmark`) and performance docs.
- Test/documentation polish and release prep.

### Changed
- README and wiki updates for the release.

## [v1.5.0] - 2026-02-18
### Changed
- README updates and version bump.
- Static analysis cleanup (`ruff` + `mypy`).

## [v1.4.1] - 2026-02-17
### Added
- Docker healthcheck and improved dev workflow.

## [v1.4.0] - 2026-01-20
### Added
- DNS + Whois enrichment.

## [v1.3.0] - 2026-01-20
### Added
- Webhook notifications with HMAC verification.

## [v1.2.0] - 2026-01-20
### Added
- `.env` support for API keys.

## [v1.1.0] - 2026-01-20
### Added
- New data sources (including AlienVault OTX).

## [v1.0.0] - 2026-01-20
### Added
- Initial release.

[v1.7.0]: https://github.com/newuni/url-reputation/compare/v1.6.0...v1.7.0
[v1.6.0]: https://github.com/newuni/url-reputation/compare/v1.5.0...v1.6.0
[v1.5.0]: https://github.com/newuni/url-reputation/compare/v1.4.1...v1.5.0
[v1.4.1]: https://github.com/newuni/url-reputation/compare/v1.4.0...v1.4.1
[v1.4.0]: https://github.com/newuni/url-reputation/compare/v1.3.0...v1.4.0
[v1.3.0]: https://github.com/newuni/url-reputation/compare/v1.2.0...v1.3.0
[v1.2.0]: https://github.com/newuni/url-reputation/compare/v1.1.0...v1.2.0
[v1.1.0]: https://github.com/newuni/url-reputation/compare/v1.0.0...v1.1.0
[v1.0.0]: https://github.com/newuni/url-reputation/releases/tag/v1.0.0
