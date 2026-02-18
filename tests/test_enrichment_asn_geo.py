from __future__ import annotations

import os
import unittest
from unittest.mock import patch

from url_reputation.enrichment.asn_geo import AsnGeoEnricher
from url_reputation.enrichment.base import EnrichmentContext


class TestAsnGeoEnricher(unittest.TestCase):
    def test_domain_resolves_to_ips_and_offline_quality(self):
        e = AsnGeoEnricher()
        with (
            patch.dict(os.environ, {"URL_REPUTATION_OFFLINE": "1"}),
            patch(
                "url_reputation.enrichment.asn_geo._resolve_domain_ips",
                return_value=["2.2.2.2", "1.1.1.1"],
            ),
        ):
            out = e.enrich("example.com", EnrichmentContext(timeout=1, indicator_type="domain"))

        self.assertEqual(out["ips"], ["1.1.1.1", "2.2.2.2"])
        self.assertIsNone(out["asn"])
        self.assertIsNone(out["geo"])
        self.assertEqual(out["quality"]["source"], "local")
        self.assertEqual(out["quality"]["confidence"], "low")
        self.assertIn("ips", out["quality"]["coverage"])
        self.assertIn("offline_mode_enabled", out["quality"]["notes"])

    def test_ip_indicator_online_success_quality_high(self):
        e = AsnGeoEnricher()
        with (
            patch.dict(os.environ, {}, clear=False),
            patch(
                "url_reputation.enrichment.asn_geo._ripe_lookup",
                return_value=(
                    {"number": 15169, "name": None, "org": "Google LLC", "prefix": "8.8.8.0/24"},
                    None,
                ),
            ),
            patch(
                "url_reputation.enrichment.asn_geo._cymru_lookup",
                return_value=(None, "cymru_lookup_failed: TimeoutError"),
            ),
            patch(
                "url_reputation.enrichment.asn_geo._ip_api_lookup",
                return_value=(
                    {
                        "country": "United States",
                        "region": "California",
                        "city": "Mountain View",
                        "lat": 37.4,
                        "lon": -122.1,
                        "isp": "Google LLC",
                        "as": "AS15169 Google LLC",
                        "org": "Google LLC",
                    },
                    None,
                ),
            ),
        ):
            out = e.enrich("8.8.8.8", EnrichmentContext(timeout=2, indicator_type="ip"))

        self.assertEqual(out["ips"], ["8.8.8.8"])
        self.assertEqual(out["asn"]["number"], 15169)
        self.assertEqual(out["geo"]["country"], "United States")
        self.assertEqual(out["quality"]["source"], "online")
        self.assertEqual(out["quality"]["confidence"], "high")
        self.assertTrue(set(out["quality"]["sources"]) >= {"ripe", "ip-api"})

    def test_network_failure_falls_back_to_local(self):
        e = AsnGeoEnricher()
        with (
            patch.dict(os.environ, {}, clear=False),
            patch(
                "url_reputation.enrichment.asn_geo._resolve_domain_ips",
                return_value=["1.2.3.4"],
            ),
            patch(
                "url_reputation.enrichment.asn_geo._ripe_lookup",
                return_value=(None, "ripe_lookup_failed: URLError"),
            ),
            patch(
                "url_reputation.enrichment.asn_geo._cymru_lookup",
                return_value=(None, "cymru_lookup_failed: TimeoutError"),
            ),
            patch(
                "url_reputation.enrichment.asn_geo._ip_api_lookup",
                return_value=(None, "ip_api_failed: URLError"),
            ),
        ):
            out = e.enrich("example.com", EnrichmentContext(timeout=1, indicator_type="domain"))

        self.assertEqual(out["ips"], ["1.2.3.4"])
        self.assertIsNone(out["asn"])
        self.assertIsNone(out["geo"])
        self.assertEqual(out["quality"]["source"], "local")
        self.assertEqual(out["quality"]["confidence"], "low")
        self.assertTrue(any("ripe_lookup_failed" in n for n in out["quality"]["notes"]))

    def test_mixed_quality_when_partial_data(self):
        e = AsnGeoEnricher()
        with (
            patch.dict(os.environ, {}, clear=False),
            patch(
                "url_reputation.enrichment.asn_geo._resolve_domain_ips",
                return_value=["1.1.1.1"],
            ),
            patch(
                "url_reputation.enrichment.asn_geo._ripe_lookup",
                return_value=(
                    {
                        "number": 13335,
                        "name": None,
                        "org": "Cloudflare, Inc.",
                        "prefix": "1.1.1.0/24",
                    },
                    None,
                ),
            ),
            patch(
                "url_reputation.enrichment.asn_geo._cymru_lookup",
                return_value=(None, None),
            ),
            patch(
                "url_reputation.enrichment.asn_geo._ip_api_lookup",
                return_value=(None, "ip_api_fail: rate limited"),
            ),
        ):
            out = e.enrich("example.com", EnrichmentContext(timeout=1, indicator_type="domain"))

        self.assertEqual(out["asn"]["number"], 13335)
        self.assertIsNone(out["geo"])
        self.assertEqual(out["quality"]["source"], "mixed")
        self.assertEqual(out["quality"]["confidence"], "medium")
        self.assertIn("asn", out["quality"]["coverage"])
        self.assertTrue(any("rate limited" in n for n in out["quality"]["notes"]))

    def test_domain_with_no_ips_reports_none_quality(self):
        e = AsnGeoEnricher()
        with (
            patch.dict(os.environ, {"URL_REPUTATION_OFFLINE": "1"}),
            patch(
                "url_reputation.enrichment.asn_geo._resolve_domain_ips",
                return_value=[],
            ),
        ):
            out = e.enrich(
                "no-a-records.invalid", EnrichmentContext(timeout=1, indicator_type="domain")
            )

        self.assertEqual(out["ips"], [])
        self.assertIsNone(out["asn"])
        self.assertIsNone(out["geo"])
        self.assertEqual(out["quality"]["source"], "none")
        self.assertIn("no_a_aaaa_records", out["quality"]["notes"])


if __name__ == "__main__":
    unittest.main()
