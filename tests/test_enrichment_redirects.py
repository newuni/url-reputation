from __future__ import annotations

import unittest
from types import SimpleNamespace
from unittest.mock import patch

from url_reputation.enrichment.base import EnrichmentContext
from url_reputation.enrichment.redirects import RedirectsEnricher


class TestRedirectsEnricher(unittest.TestCase):
    def test_redirects_enricher_skips_non_url(self):
        e = RedirectsEnricher(max_hops=2)
        out = e.enrich("example.com", EnrichmentContext(timeout=1, indicator_type="domain"))
        self.assertTrue(out.get("skipped"))

    def test_redirects_enricher_returns_shape_for_url(self):
        e = RedirectsEnricher(max_hops=5)

        # Fully offline test: mock urllib to simulate one 301 hop then 200.
        calls = {"n": 0}

        def _fake_urlopen(req, timeout=0):  # noqa: ARG001
            calls["n"] += 1
            if calls["n"] == 1:
                return SimpleNamespace(
                    status=301, headers={"Location": "https://www.example.com/"}, read=lambda: b""
                )
            return SimpleNamespace(status=200, headers={}, read=lambda: b"")

        with patch("url_reputation.enrichment.redirects.urlopen", _fake_urlopen):
            out = e.enrich(
                "http://example.com", EnrichmentContext(timeout=10, indicator_type="url")
            )

        self.assertIn("chain", out)
        self.assertIsInstance(out["chain"], list)
        self.assertIn("hops", out)
        self.assertIn("final_url", out)


if __name__ == "__main__":
    unittest.main()
