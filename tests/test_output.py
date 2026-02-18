import unittest

from url_reputation.output import (
    exit_code_from_results,
    exit_code_from_verdict,
    to_sarif,
    verdict_level,
    worst_verdict,
)


class TestOutputHelpers(unittest.TestCase):
    def test_verdict_level_unknown_maps_to_error(self):
        self.assertEqual(verdict_level("NOT_A_VERDICT"), verdict_level("ERROR"))

    def test_worst_verdict(self):
        self.assertEqual(worst_verdict("CLEAN", "HIGH_RISK"), "HIGH_RISK")
        self.assertEqual(worst_verdict("ERROR", "LOW_RISK"), "ERROR")

    def test_exit_code_from_verdict_defaults(self):
        self.assertEqual(exit_code_from_verdict("CLEAN", fail_on=None), 0)
        self.assertEqual(exit_code_from_verdict("ERROR", fail_on=None), 2)

    def test_exit_code_from_verdict_with_fail_on(self):
        self.assertEqual(exit_code_from_verdict("LOW_RISK", fail_on="MEDIUM_RISK"), 0)
        self.assertEqual(exit_code_from_verdict("HIGH_RISK", fail_on="MEDIUM_RISK"), 1)
        self.assertEqual(exit_code_from_verdict("ERROR", fail_on="HIGH_RISK"), 1)

    def test_exit_code_from_results(self):
        results = [{"verdict": "CLEAN"}, {"verdict": "MEDIUM_RISK"}, {}]
        self.assertEqual(exit_code_from_results(results, fail_on="HIGH_RISK"), 1)
        self.assertEqual(exit_code_from_results(results, fail_on="ERROR"), 1)

    def test_to_sarif_shapes_levels_and_url_fallback(self):
        results = [
            {"url": "https://a.test", "verdict": "CLEAN", "risk_score": 0},
            {"indicator": {"input": "b.test"}, "verdict": "LOW_RISK", "risk_score": 30},
            {"url": "https://c.test", "verdict": "HIGH_RISK", "risk_score": 90},
        ]
        sarif = to_sarif(results)

        self.assertEqual(sarif["version"], "2.1.0")
        run = sarif["runs"][0]
        self.assertEqual(run["tool"]["driver"]["name"], "url-reputation")
        self.assertEqual(len(run["results"]), 3)
        self.assertEqual(run["results"][0]["level"], "note")
        self.assertEqual(run["results"][1]["level"], "warning")
        self.assertEqual(run["results"][2]["level"], "error")
        self.assertIn("b.test", run["results"][1]["message"]["text"])


if __name__ == "__main__":
    unittest.main()
