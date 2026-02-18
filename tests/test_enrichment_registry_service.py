import unittest
from unittest.mock import MagicMock, patch

from url_reputation.enrichment.base import Enricher, EnrichmentContext
from url_reputation.enrichment.registry import EnrichmentRegistry, _iter_entry_points
from url_reputation.enrichment.service import enrich_domain, enrich_indicator


class DummyEnricher(Enricher):
    def __init__(self, name: str):
        self.name = name

    def enrich(self, indicator: str, ctx: EnrichmentContext):
        return {
            "indicator": indicator,
            "indicator_type": ctx.indicator_type,
            "timeout": ctx.timeout,
        }


class TestEnrichmentRegistry(unittest.TestCase):
    @patch("url_reputation.enrichment.registry.metadata.entry_points")
    def test_iter_entry_points_select_api(self, mock_eps):
        selected = [MagicMock(), MagicMock()]
        container = MagicMock()
        container.select.return_value = selected
        mock_eps.return_value = container

        out = _iter_entry_points("url_reputation.enrichers")
        self.assertEqual(out, selected)

    @patch("url_reputation.enrichment.registry.metadata.entry_points")
    def test_iter_entry_points_dict_api(self, mock_eps):
        ep = MagicMock()
        mock_eps.return_value = {"url_reputation.enrichers": [ep]}
        out = _iter_entry_points("url_reputation.enrichers")
        self.assertEqual(out, [ep])

    @patch("url_reputation.enrichment.registry.metadata.entry_points")
    def test_iter_entry_points_iterable_fallback(self, mock_eps):
        ep_match = MagicMock()
        ep_match.group = "url_reputation.enrichers"
        ep_other = MagicMock()
        ep_other.group = "other"
        mock_eps.return_value = [ep_other, ep_match]

        out = _iter_entry_points("url_reputation.enrichers")
        self.assertEqual(out, [ep_match])

    @patch("url_reputation.enrichment.registry._iter_entry_points")
    def test_load_entrypoints_accepts_instance_and_factory(self, mock_iter):
        ep_factory = MagicMock()
        ep_factory.load.return_value = lambda: DummyEnricher("factory")

        ep_instance = MagicMock()
        ep_instance.load.return_value = DummyEnricher("instance")

        ep_invalid = MagicMock()
        ep_invalid.load.return_value = object()

        mock_iter.return_value = [ep_factory, ep_instance, ep_invalid]

        loaded = EnrichmentRegistry.load_entrypoints()
        self.assertIn("factory", loaded)
        self.assertIn("instance", loaded)
        self.assertNotIn("invalid", loaded)

    def test_select_and_list_names(self):
        reg = EnrichmentRegistry({"dns": DummyEnricher("dns"), "whois": DummyEnricher("whois")})
        self.assertEqual(reg.list_names(), ["dns", "whois"])
        self.assertEqual([e.name for e in reg.select(["whois", "missing"])], ["whois"])


class TestEnrichmentService(unittest.TestCase):
    @patch("url_reputation.enrichment.service.builtin_enrichers")
    def test_enrich_indicator_url_feeds_host_for_dns_whois(self, mock_builtin):
        dns = DummyEnricher("dns")
        whois = DummyEnricher("whois")
        redirects = DummyEnricher("redirects")
        mock_builtin.return_value = {"dns": dns, "whois": whois, "redirects": redirects}

        out = enrich_indicator(
            "https://sub.example.com/path",
            indicator_type="url",
            types=["dns", "whois", "redirects"],
            timeout=12,
        )

        self.assertEqual(out["dns"]["indicator"], "sub.example.com")
        self.assertEqual(out["whois"]["indicator"], "sub.example.com")
        self.assertEqual(out["redirects"]["indicator"], "https://sub.example.com/path")

    @patch("url_reputation.enrichment.service.builtin_enrichers")
    def test_enrich_domain_alias(self, mock_builtin):
        dns = DummyEnricher("dns")
        mock_builtin.return_value = {"dns": dns}

        out = enrich_domain("example.com", types=["dns"], timeout=5)
        self.assertEqual(out["dns"]["indicator_type"], "domain")


if __name__ == "__main__":
    unittest.main()
