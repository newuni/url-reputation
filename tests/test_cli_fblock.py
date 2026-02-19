from __future__ import annotations

from io import StringIO
from unittest.mock import patch

from url_reputation.cli import parse_interval_seconds, print_enrichment


def test_parse_interval_seconds_variants() -> None:
    assert parse_interval_seconds("30") == 30
    assert parse_interval_seconds("30s") == 30
    assert parse_interval_seconds("2m") == 120
    assert parse_interval_seconds("1h") == 3600
    assert parse_interval_seconds("500ms") == 1
    assert parse_interval_seconds("bad") is None
    assert parse_interval_seconds(None) is None


def test_print_enrichment_new_sections() -> None:
    enrichment = {
        "dns": {
            "a_records": ["1.1.1.1"],
            "aaaa_records": ["::1"],
            "mx_records": ["mx1.example.com"],
            "ns_records": ["ns1.example.com"],
            "has_spf": True,
            "has_dmarc": False,
        },
        "whois": {
            "creation_date": "2026-01-01T00:00:00Z",
            "domain_age_days": 10,
            "is_new_domain": True,
            "registrar": "Example Registrar",
            "registrant_country": "ES",
        },
        "asn_geo": {
            "ips": ["1.1.1.1"],
            "asn": {"number": 13335, "org": "Cloudflare"},
            "geo": {"city": "Bilbao", "region": "PV", "country": "ES"},
        },
        "ssl": {
            "issuer": "Test CA",
            "not_after": "2030-01-01T00:00:00Z",
            "days_to_expiry": 365,
            "self_signed": True,
            "hostname_match": False,
        },
        "screenshot": {"path": "/tmp/shot.png"},
        "risk_indicators": ["A", "B"],
    }

    with patch("sys.stdout", new=StringIO()) as mock_stdout:
        print_enrichment(enrichment)
        out = mock_stdout.getvalue()

    assert "ASN/Geo" in out
    assert "TLS Certificate" in out
    assert "Screenshot" in out
    assert "Risk Indicators" in out
