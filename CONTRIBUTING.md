# Contributing to URL Reputation Checker

Thank you for your interest in contributing! This document provides guidelines for setting up the development environment, running tests, and submitting changes.

## Development Setup

### Prerequisites

- Python 3.9 or higher
- Git

### Clone and Setup

```bash
# Clone the repository
git clone https://github.com/newuni/url-reputation.git
cd url-reputation

# Create virtual environment
python -m venv .venv
source .venv/bin/activate  # On Windows: .venv\Scripts\activate

# Install in development mode with all dependencies
pip install -e ".[full,dev]"
```

### Alternative: Using Docker

```bash
# Build and run tests in Docker
docker compose -f docker-compose.test.yml up --build
```

## Running Tests

### Quick Test Run

```bash
# Run all tests
pytest

# Run with verbose output
pytest -v

# Run with coverage report
pytest --cov=url_reputation --cov-report=term-missing
```

### Specific Test Files

```bash
# Run specific test file
pytest tests/test_checker.py

# Run specific test
pytest tests/test_checker.py::TestReputationChecker::test_single_url
```

### Benchmarks

```bash
# Run performance benchmarks
pytest tests/ --benchmark-only
```

## Code Quality

Before submitting changes, ensure all quality checks pass:

```bash
# Run all quality checks (do this before committing)
pytest                    # All tests must pass
ruff check .              # Linting must pass
mypy url_reputation       # Type checking must pass
```

### Linting with Ruff

```bash
# Check for issues
ruff check .

# Auto-fix issues where possible
ruff check . --fix

# Check specific directory
ruff check url_reputation/
```

### Type Checking with mypy

```bash
# Type check the main package
mypy url_reputation

# Strict mode (for new code)
mypy url_reputation --strict
```

## Commit Conventions

We use [Conventional Commits](https://www.conventionalcommits.org/) for clear and structured commit messages.

### Format

```
<type>(<scope>): <description>

[optional body]

[optional footer(s)]
```

### Types

| Type | Description |
|------|-------------|
| `feat` | New feature |
| `fix` | Bug fix |
| `docs` | Documentation changes |
| `style` | Code style changes (formatting, semicolons, etc.) |
| `refactor` | Code refactoring without changing behavior |
| `perf` | Performance improvements |
| `test` | Adding or correcting tests |
| `chore` | Maintenance tasks (deps, build, etc.) |

### Scopes

Common scopes for this project:

- `providers` - Reputation provider changes
- `cache` - Caching functionality
- `cli` - Command-line interface
- `api` - Public API changes
- `models` - Data models
- `enrich` - Enrichment modules
- `docs` - Documentation
- `tests` - Test suite

### Examples

```bash
# Feature
git commit -m "feat(providers): add AlienVault OTX provider"

# Bug fix
git commit -m "fix(cache): handle TTL parsing edge case with '0'"

# Documentation
git commit -m "docs(adr): add ADR for provider registry design"

# Breaking change
git commit -m "feat(api): change ResultV1 structure

BREAKING CHANGE: sources field now returns list instead of dict"
```

## Pull Request Checklist

Before submitting a PR, ensure:

- [ ] **Tests pass**: `pytest` completes with no failures
- [ ] **Linting passes**: `ruff check .` reports no issues
- [ ] **Type checking passes**: `mypy url_reputation` succeeds
- [ ] **Documentation updated**: README, schema docs, or ADRs updated if needed
- [ ] **Commit messages follow conventions**: Use Conventional Commits format
- [ ] **Changelog entry added**: If applicable, add to unreleased section
- [ ] **PR description is clear**: Explain what, why, and how

### PR Title Format

Same as commit convention:

```
<type>(<scope>): Brief description
```

Example: `feat(providers): add ThreatFox API integration`

## Project Structure

```
url-reputation/
├── url_reputation/          # Main package
│   ├── providers/           # Reputation source providers
│   ├── sources/             # Built-in source implementations
│   ├── enrichment/          # Enrichment modules (DNS, Whois, etc.)
│   ├── cache.py             # Caching functionality
│   ├── models.py            # Data models (Schema v1)
│   ├── checker.py           # Main reputation checker
│   └── cli.py               # Command-line interface
├── tests/                   # Test suite
├── docs/                    # Documentation
│   ├── adr/                 # Architecture Decision Records
│   ├── schema-v1.md         # Schema documentation
│   └── plugins.md           # Plugin development guide
├── scripts/                 # Utility scripts
├── web/                     # Docker web UI
├── wiki/                    # Project wiki/status
└── references/              # API references and guides
```

## Adding a New Provider

1. Create provider class in `url_reputation/providers/` or `url_reputation/sources/`
2. Inherit from `Provider` base class
3. Implement `is_available()` and `check()` methods
4. Register in `url_reputation/providers/builtins.py`
5. Add tests in `tests/`
6. Update README with provider documentation

Example:

```python
from url_reputation.providers.base import Provider

class MyProvider(Provider):
    name = "myprovider"
    
    def is_available(self) -> bool:
        return bool(os.getenv("MY_API_KEY"))
    
    async def check(self, indicator: str) -> dict[str, Any]:
        # Implementation here
        return {"listed": False, "details": {}}
```

## Questions?

- Open an issue for discussion
- Check existing issues and ADRs in `docs/adr/`
- Read `docs/plugins.md` for plugin development

## License

By contributing, you agree that your contributions will be licensed under the MIT License.
