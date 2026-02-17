"""Output helpers (SARIF, verdict severity, exit codes)."""

from __future__ import annotations

from typing import Any

_VERDICT_ORDER = ["CLEAN", "LOW_RISK", "MEDIUM_RISK", "HIGH_RISK", "ERROR"]


def verdict_level(v: str) -> int:
    try:
        return _VERDICT_ORDER.index(v)
    except ValueError:
        return _VERDICT_ORDER.index("ERROR")


def worst_verdict(a: str, b: str) -> str:
    return a if verdict_level(a) >= verdict_level(b) else b


def exit_code_from_verdict(verdict: str, *, fail_on: str | None) -> int:
    # Default: always 0
    if fail_on is None:
        return 0 if verdict != "ERROR" else 2

    if verdict_level(verdict) >= verdict_level(fail_on):
        return 1

    return 0 if verdict != "ERROR" else 2


def exit_code_from_results(results: list[dict[str, Any]], *, fail_on: str | None) -> int:
    worst = "CLEAN"
    for r in results:
        worst = worst_verdict(worst, r.get("verdict", "ERROR"))
    return exit_code_from_verdict(worst, fail_on=fail_on)


def to_sarif(results: list[dict[str, Any]]) -> dict[str, Any]:
    """Minimal SARIF 2.1.0 output."""

    sarif_results = []
    for r in results:
        url = r.get("url") or r.get("indicator", {}).get("input")
        verdict = r.get("verdict", "ERROR")
        score = r.get("risk_score", 0)

        level = "note"
        if verdict in ("LOW_RISK",):
            level = "warning"
        elif verdict in ("MEDIUM_RISK", "HIGH_RISK", "ERROR"):
            level = "error"

        sarif_results.append(
            {
                "ruleId": "url-reputation",
                "level": level,
                "message": {"text": f"{verdict} ({score}/100) for {url}"},
                "locations": [
                    {
                        "physicalLocation": {
                            "artifactLocation": {"uri": url or ""},
                        }
                    }
                ],
            }
        )

    return {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "url-reputation",
                        "informationUri": "https://github.com/newuni/url-reputation",
                        "rules": [
                            {
                                "id": "url-reputation",
                                "name": "URL Reputation",
                                "shortDescription": {"text": "Unified URL/domain reputation check"},
                            }
                        ],
                    }
                },
                "results": sarif_results,
            }
        ],
    }
