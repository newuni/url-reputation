from __future__ import annotations

from url_reputation.html_report import to_html_batch, to_html_single


def test_to_html_single_contains_verdict_and_sources() -> None:
    result = {
        "url": "https://example.com",
        "domain": "example.com",
        "verdict": "LOW_RISK",
        "risk_score": 42,
        "checked_at": "2026-02-19T00:00:00Z",
        "sources": [{"name": "urlhaus", "status": "ok", "raw": {"threat_type": "malware"}}],
        "enrichment": {"whois": {"registrar": "Example Registrar"}},
    }

    html = to_html_single(result)
    assert "URL Reputation Report" in html
    assert "LOW_RISK" in html
    assert "urlhaus" in html
    assert "Enrichment" in html


def test_to_html_batch_contains_rows() -> None:
    payload = [
        {"url": "https://a.test", "verdict": "CLEAN", "risk_score": 0},
        {"url": "https://b.test", "verdict": "HIGH_RISK", "risk_score": 99},
    ]

    html = to_html_batch(payload)
    assert "URL Reputation Batch Report" in html
    assert "https://a.test" in html
    assert "https://b.test" in html
    assert "HIGH_RISK" in html
