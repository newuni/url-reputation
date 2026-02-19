"""Simple standalone HTML report rendering."""

from __future__ import annotations

from html import escape
from typing import Any


def _badge(verdict: str) -> str:
    colors = {
        "CLEAN": "#16a34a",
        "LOW_RISK": "#ca8a04",
        "MEDIUM_RISK": "#ea580c",
        "HIGH_RISK": "#dc2626",
        "ERROR": "#991b1b",
    }
    c = colors.get(verdict, "#6b7280")
    return f'<span style="background:{c};color:white;padding:3px 8px;border-radius:12px;font-size:12px">{escape(verdict)}</span>'


def to_html_single(result: dict[str, Any]) -> str:
    rows = []
    for s in result.get("sources", []):
        name = escape(str(s.get("name", "unknown")))
        status = escape(str(s.get("status", "ok")))
        err = s.get("error")
        detail = (
            escape(str(err)) if err else escape(str((s.get("raw") or {}).get("threat_type", "")))
        )
        rows.append(f"<tr><td>{name}</td><td>{status}</td><td>{detail}</td></tr>")

    enrichment_html = ""
    enrichment = result.get("enrichment")
    if enrichment:
        enrichment_html = f"<h3>Enrichment</h3><pre>{escape(str(enrichment))}</pre>"

    return f"""<!doctype html><html><head><meta charset='utf-8'><title>URL Reputation Report</title>
<style>body{{font-family:system-ui;max-width:980px;margin:24px auto;padding:0 12px}}table{{width:100%;border-collapse:collapse}}td,th{{border:1px solid #ddd;padding:8px;text-align:left}}th{{background:#f3f4f6}}</style>
</head><body>
<h1>URL Reputation Report</h1>
<p><b>Target:</b> {escape(str(result.get("url", "")))}</p>
<p><b>Domain:</b> {escape(str(result.get("domain", "")))}</p>
<p><b>Verdict:</b> {_badge(str(result.get("verdict", "UNKNOWN")))} &nbsp; <b>Score:</b> {escape(str(result.get("risk_score", 0)))}/100</p>
<h3>Sources</h3>
<table><thead><tr><th>Source</th><th>Status</th><th>Details</th></tr></thead><tbody>{"".join(rows)}</tbody></table>
{enrichment_html}
<p style='color:#666'>Checked at: {escape(str(result.get("checked_at", "")))}</p>
</body></html>"""


def to_html_batch(results: list[dict[str, Any]]) -> str:
    rows = []
    for r in results:
        rows.append(
            "<tr>"
            f"<td>{escape(str(r.get('url', '')))}</td>"
            f"<td>{_badge(str(r.get('verdict', 'UNKNOWN')))}</td>"
            f"<td>{escape(str(r.get('risk_score', 0)))}</td>"
            "</tr>"
        )

    return f"""<!doctype html><html><head><meta charset='utf-8'><title>URL Reputation Batch Report</title>
<style>body{{font-family:system-ui;max-width:980px;margin:24px auto;padding:0 12px}}table{{width:100%;border-collapse:collapse}}td,th{{border:1px solid #ddd;padding:8px;text-align:left}}th{{background:#f3f4f6}}</style>
</head><body>
<h1>URL Reputation Batch Report</h1>
<table><thead><tr><th>URL</th><th>Verdict</th><th>Score</th></tr></thead><tbody>{"".join(rows)}</tbody></table>
</body></html>"""
