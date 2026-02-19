from __future__ import annotations

from typing import Any

from url_reputation.enrichment.base import EnrichmentContext
from url_reputation.enrichment.ssl import SslCertEnricher


class _FakeSocket:
    def __enter__(self) -> _FakeSocket:
        return self

    def __exit__(self, exc_type: Any, exc: Any, tb: Any) -> None:
        return None


class _FakeWrapped:
    def __init__(self, cert: dict[str, Any]) -> None:
        self._cert = cert

    def __enter__(self) -> _FakeWrapped:
        return self

    def __exit__(self, exc_type: Any, exc: Any, tb: Any) -> None:
        return None

    def getpeercert(self) -> dict[str, Any]:
        return self._cert


class _FakeContext:
    def __init__(self, cert: dict[str, Any]) -> None:
        self._cert = cert
        self.check_hostname = False

    def wrap_socket(self, sock: Any, server_hostname: str | None = None) -> _FakeWrapped:
        return _FakeWrapped(self._cert)


def test_ssl_enricher_happy_path(monkeypatch: Any) -> None:
    cert = {
        "subject": ((("commonName", "example.com"),),),
        "issuer": ((("commonName", "Test CA"),),),
        "subjectAltName": (("DNS", "example.com"), ("DNS", "*.example.com")),
        "notBefore": "Jan 01 00:00:00 2026 GMT",
        "notAfter": "Jan 01 00:00:00 2030 GMT",
    }

    monkeypatch.setattr("socket.create_connection", lambda *a, **k: _FakeSocket())
    monkeypatch.setattr("ssl.create_default_context", lambda: _FakeContext(cert))

    enricher = SslCertEnricher()
    out = enricher.enrich("example.com", EnrichmentContext(timeout=5, indicator_type="domain"))

    assert out["valid"] is True
    assert "Test CA" in str(out["issuer"])
    assert out["hostname_match"] is True
    assert isinstance(out["san"], list)


def test_ssl_enricher_error_path(monkeypatch: Any) -> None:
    def _boom(*args: Any, **kwargs: Any) -> Any:
        raise RuntimeError("network down")

    monkeypatch.setattr("socket.create_connection", _boom)

    enricher = SslCertEnricher()
    out = enricher.enrich("example.com", EnrichmentContext(timeout=5, indicator_type="domain"))

    assert out["valid"] is False
    assert "error" in out
