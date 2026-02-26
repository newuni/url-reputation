# AGENTS.md

## Release Checklist (Required)

When a release is declared (for example `vX.Y.Z`), always complete these steps before finishing:

1. Update `CHANGELOG.md` with a new section for that exact version.
2. Add/update the comparison link reference for the new version at the bottom of `CHANGELOG.md`.
3. Ensure README release-facing docs are aligned with the shipped features.
4. Verify version numbers are consistent (`pyproject.toml`, `url_reputation/__init__.py`, and API version if applicable).

Do not publish a release if `CHANGELOG.md` is missing or stale.
