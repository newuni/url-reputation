"""Markdown report formatter for url-reputation.

This is a presentation-only layer (derived from schema v1 results).
"""

from __future__ import annotations

import re
from typing import Any

from .output import worst_verdict


def _md_code(value: Any) -> str:
    """Render an inline code span, handling backticks safely."""
    if value is None:
        return "-"
    s = str(value)
    ticks = 0
    for m in re.finditer(r"`+", s):
        ticks = max(ticks, len(m.group(0)))
    delim = "`" * (ticks + 1)
    if s.startswith(" ") or s.endswith(" "):
        return f"{delim} {s} {delim}"
    return f"{delim}{s}{delim}"


def _cell(value: Any) -> str:
    """Escape text for use in a Markdown table cell."""
    if value is None:
        return "-"
    s = str(value).replace("\r", "").replace("\n", " ")
    # Tables use '|' as a delimiter.
    return s.replace("|", "\\|")


def _indicator_fields(result: dict[str, Any]) -> tuple[str, str, str, str]:
    ind = result.get("indicator") or {}
    if not isinstance(ind, dict):
        ind = {}

    input_ = ind.get("input") or result.get("url") or result.get("domain") or "unknown"
    typ = ind.get("type") or "unknown"
    canonical = ind.get("canonical") or input_
    domain = ind.get("domain")
    if domain is None:
        domain = result.get("domain") or "-"
    return str(input_), str(typ), str(canonical), str(domain)


def to_markdown_single(result: dict[str, Any]) -> str:
    """Render a single ResultV1-ish dict to Markdown."""
    input_, typ, canonical, domain = _indicator_fields(result)

    verdict = result.get("verdict", "ERROR")
    risk_score = result.get("risk_score", "-")
    checked_at = result.get("checked_at", "-")

    out: list[str] = []
    out.append("# URL Reputation Report")
    out.append("")
    out.append(f"- Indicator: {_md_code(input_)}")
    out.append(f"- Type: {_md_code(typ)}")
    out.append(f"- Canonical: {_md_code(canonical)}")
    out.append(f"- Domain: {_md_code(domain)}")
    out.append(f"- Verdict: {_md_code(verdict)}")
    if risk_score in (None, "-"):
        risk_score_display = "-"
    else:
        risk_score_display = f"{risk_score}/100"
    out.append(f"- Risk score: {_md_code(risk_score_display)}")
    out.append(f"- Checked at: {_md_code(checked_at)}")
    out.append("")
    out.append("## Sources")
    out.append("")

    sources = result.get("sources") or []
    if isinstance(sources, dict):
        # Legacy-ish shape: {name: payload}
        sources = [{"name": k, "status": "ok", "raw": v} for k, v in sources.items()]
    if not isinstance(sources, list):
        sources = []

    if not sources:
        out.append("_No sources._")
        out.append("")
        return "\n".join(out)

    # Deterministic ordering.
    sources_sorted = sorted(sources, key=lambda s: str((s or {}).get("name", "")))

    out.append("| Source | Status | Listed | Score | Error |")
    out.append("| --- | --- | --- | --- | --- |")
    for src in sources_sorted:
        if not isinstance(src, dict):
            continue
        name = _cell(src.get("name", "unknown"))
        status = _cell(src.get("status", "-"))
        listed = src.get("listed")
        if listed is True:
            listed_s = "true"
        elif listed is False:
            listed_s = "false"
        else:
            listed_s = "-"
        score = src.get("score")
        score_s = "-" if score is None else _cell(score)
        err = _cell(src.get("error"))
        out.append(f"| {name} | {status} | {listed_s} | {score_s} | {err} |")

    out.append("")
    return "\n".join(out)


def to_markdown_batch(results: list[dict[str, Any]]) -> str:
    """Render a batch report to Markdown, including a summary at the end."""
    out: list[str] = []
    out.append("# URL Reputation Batch Report")
    out.append("")
    out.append("## Results")
    out.append("")

    # Deterministic ordering: results from run_batch() can arrive in completion order.
    def sort_key(r: dict[str, Any]) -> str:
        input_, _, canonical, _ = _indicator_fields(r)
        return canonical or input_

    results_sorted = sorted((r for r in results if isinstance(r, dict)), key=sort_key)

    out.append("| Indicator | Type | Verdict | Risk | Domain | Error |")
    out.append("| --- | --- | --- | --- | --- | --- |")
    for r in results_sorted:
        input_, typ, _, domain = _indicator_fields(r)
        verdict = r.get("verdict", "ERROR")
        risk_score = r.get("risk_score", "-")
        risk = f"{risk_score}/100" if risk_score != "-" else "-"
        err = r.get("error")
        out.append(
            f"| {_md_code(_cell(input_))} | {_md_code(_cell(typ))} | {_md_code(_cell(verdict))} | {_md_code(_cell(risk))} | {_md_code(_cell(domain))} | {_cell(err)} |"
        )

    # Summary (must be at end for batch runs).
    total = len(results_sorted)
    counts: dict[str, int] = {}
    worst = "CLEAN"
    errors: list[tuple[str, str]] = []
    for r in results_sorted:
        v = str(r.get("verdict") or "ERROR")
        counts[v] = counts.get(v, 0) + 1
        worst = worst_verdict(worst, v)
        e = r.get("error")
        if v == "ERROR" or e:
            input_, _, _, _ = _indicator_fields(r)
            errors.append((str(input_), str(e) if e else "Unknown error"))

    out.append("")
    out.append("## Summary")
    out.append("")
    out.append(f"- Total: {_md_code(total)}")
    out.append(f"- Worst verdict: {_md_code(worst)}")
    out.append("- Counts by verdict:")
    for verdict in sorted(counts.keys()):
        out.append(f"  - {verdict}: {counts[verdict]}")
    out.append(f"- Errors: {_md_code(len(errors))}")

    if errors:
        out.append("")
        out.append("### Error details")
        out.append("")
        out.append("| Indicator | Error |")
        out.append("| --- | --- |")
        errors_sorted = sorted(errors, key=lambda t: t[0])
        max_rows = 20
        for ind, msg in errors_sorted[:max_rows]:
            out.append(f"| {_md_code(_cell(ind))} | {_cell(msg)} |")
        if len(errors_sorted) > max_rows:
            out.append("")
            out.append(f"_({len(errors_sorted) - max_rows} more errors omitted.)_")

    out.append("")
    return "\n".join(out)
