import unittest
from unittest.mock import patch

from url_reputation.scoring import aggregate_risk_score


class TestScoringDeterminism(unittest.TestCase):
    def test_deterministic_breakdown_order(self):
        a = {
            "phishtank": {"listed": True},
            "urlhaus": {"listed": True},
            "virustotal": {"detected": 35, "total": 70},
        }
        b = {
            "virustotal": {"detected": 35, "total": 70},
            "urlhaus": {"listed": True},
            "phishtank": {"listed": True},
        }

        agg1 = aggregate_risk_score(
            a, provider_weights={"phishtank": 1.0, "urlhaus": 1.0, "virustotal": 1.0}
        )
        agg2 = aggregate_risk_score(
            b, provider_weights={"phishtank": 1.0, "urlhaus": 1.0, "virustotal": 1.0}
        )

        self.assertEqual(agg1.risk_score, agg2.risk_score)
        self.assertEqual(agg1.verdict, agg2.verdict)
        self.assertEqual(agg1.score_breakdown, agg2.score_breakdown)
        self.assertEqual(agg1.reasons, agg2.reasons)


class TestScoringWeights(unittest.TestCase):
    def test_provider_weights_applied(self):
        results = {
            "phishtank": {"listed": True},  # base 35
            "urlhaus": {"listed": True},  # base 40
        }

        agg = aggregate_risk_score(
            results,
            provider_weights={"phishtank": 0.5, "urlhaus": 2.0},
        )

        # 35*0.5 = 17.5 -> 18 (round half up); 40*2.0 = 80; total = 98.
        self.assertEqual(agg.risk_score, 98)
        self.assertEqual(agg.verdict, "HIGH_RISK")

        by_provider = {c["provider"]: c for c in agg.score_breakdown}
        self.assertEqual(by_provider["phishtank"]["weighted_points"], 18)
        self.assertEqual(by_provider["urlhaus"]["weighted_points"], 80)


class TestScoringExplainability(unittest.TestCase):
    def test_redirects_and_domain_age_rules(self):
        enrichment = {
            "redirects": {
                "final_url": "https://final.example/path",
                "hops": 2,
                "chain": [
                    {
                        "url": "http://start.example",
                        "status": 301,
                        "location": "https://other.example/",
                    },
                    {
                        "url": "https://other.example/",
                        "status": 302,
                        "location": "https://final.example/path",
                    },
                    {"url": "https://final.example/path", "status": 200, "location": None},
                ],
            },
            "whois": {"domain_age_days": 3, "creation_date": "2026-02-15T00:00:00Z"},
        }

        agg = aggregate_risk_score(
            {}, enrichment=enrichment, provider_weights={"redirects": 1.0, "whois": 1.0}
        )

        # redirects: hops=2 => 5 + cross-domain 5 => 10; whois: <7 days => 25; total 35.
        self.assertEqual(agg.risk_score, 35)
        self.assertEqual(agg.verdict, "LOW_RISK")

        rule_ids = [c["rule_id"] for c in agg.score_breakdown]
        self.assertIn("enrichment.redirects.hops", rule_ids)
        self.assertIn("enrichment.whois.domain_age", rule_ids)
        self.assertTrue(
            any("Redirects observed" in r or "Multiple redirects" in r for r in agg.reasons)
        )
        self.assertTrue(any("Very new domain" in r for r in agg.reasons))


class TestCheckerOutputExplainability(unittest.TestCase):
    def test_check_url_includes_breakdown_and_reasons(self):
        from url_reputation.checker import check_url_reputation
        from url_reputation.providers import Provider, ProviderContext, Registry

        class _DummyProvider(Provider):
            name = "phishtank"

            def check(self, indicator: str, domain: str, ctx: ProviderContext):
                return {"listed": True}

        with patch(
            "url_reputation.checker.get_default_registry",
            return_value=Registry({"phishtank": _DummyProvider()}),
        ):
            result = check_url_reputation("https://example.com", sources=["phishtank"], timeout=1)

        self.assertIn("score_breakdown", result)
        self.assertIn("reasons", result)
        self.assertIsInstance(result["score_breakdown"], list)
        self.assertIsInstance(result["reasons"], list)
        self.assertGreaterEqual(len(result["score_breakdown"]), 1)


if __name__ == "__main__":
    unittest.main()
