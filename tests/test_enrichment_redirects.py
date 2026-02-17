from __future__ import annotations

from url_reputation.enrichment.base import EnrichmentContext
from url_reputation.enrichment.redirects import RedirectsEnricher


def test_redirects_enricher_skips_non_url():
    e = RedirectsEnricher(max_hops=2)
    out = e.enrich("example.com", EnrichmentContext(timeout=1, indicator_type="domain"))
    assert out.get("skipped") is True


def test_redirects_enricher_returns_shape_for_url():
    # We use an URL that is *expected* to be stable and typically redirects.
    # This test is intentionally loose to avoid brittle assumptions.
    e = RedirectsEnricher(max_hops=5)
    out = e.enrich("http://example.com", EnrichmentContext(timeout=10, indicator_type="url"))

    # Must include chain and hops.
    assert "chain" in out
    assert isinstance(out["chain"], list)
    assert "hops" in out

    # If it worked, final_url is present; if max redirects exceeded, an error is present.
    assert ("final_url" in out) or (out.get("error") == "max_redirects_exceeded")
