import unittest

from url_reputation.markdown import to_markdown_batch, to_markdown_single


class TestMarkdownFormatter(unittest.TestCase):
    def test_markdown_single_golden(self):
        result = {
            "schema_version": "1",
            "indicator": {
                "input": "https://b.example/path",
                "type": "url",
                "canonical": "https://b.example/path",
                "domain": "b.example",
            },
            "verdict": "LOW_RISK",
            "risk_score": 25,
            "checked_at": "2026-02-18T00:00:00+00:00",
            "sources": [
                {
                    "name": "virustotal",
                    "status": "ok",
                    "listed": None,
                    "score": 1.0,
                    "raw": {"detected": 1, "total": 70},
                    "error": None,
                    "rate_limit": None,
                    "rate_limit_info": None,
                },
                {
                    "name": "urlhaus",
                    "status": "error",
                    "listed": None,
                    "score": None,
                    "raw": {},
                    "error": "timeout",
                    "rate_limit": None,
                    "rate_limit_info": None,
                },
            ],
        }

        expected = (
            "# URL Reputation Report\n"
            "\n"
            "- Indicator: `https://b.example/path`\n"
            "- Type: `url`\n"
            "- Canonical: `https://b.example/path`\n"
            "- Domain: `b.example`\n"
            "- Verdict: `LOW_RISK`\n"
            "- Risk score: `25/100`\n"
            "- Checked at: `2026-02-18T00:00:00+00:00`\n"
            "\n"
            "## Sources\n"
            "\n"
            "| Source | Status | Listed | Score | Error |\n"
            "| --- | --- | --- | --- | --- |\n"
            "| urlhaus | error | - | - | timeout |\n"
            "| virustotal | ok | - | 1.0 | - |\n"
        )

        self.assertEqual(to_markdown_single(result), expected)

    def test_markdown_batch_golden_summary_is_deterministic(self):
        results = [
            {
                "schema_version": "1",
                "indicator": {
                    "input": "https://c.example",
                    "type": "url",
                    "canonical": "https://c.example",
                    "domain": "c.example",
                },
                "verdict": "ERROR",
                "risk_score": "-",
                "checked_at": "2026-02-18T00:00:00+00:00",
                "error": "boom",
                "sources": [],
            },
            {
                "schema_version": "1",
                "indicator": {
                    "input": "https://a.example",
                    "type": "url",
                    "canonical": "https://a.example",
                    "domain": "a.example",
                },
                "verdict": "CLEAN",
                "risk_score": 0,
                "checked_at": "2026-02-18T00:00:00+00:00",
                "sources": [],
            },
            {
                "schema_version": "1",
                "indicator": {
                    "input": "https://b.example",
                    "type": "url",
                    "canonical": "https://b.example",
                    "domain": "b.example",
                },
                "verdict": "HIGH_RISK",
                "risk_score": 90,
                "checked_at": "2026-02-18T00:00:00+00:00",
                "sources": [],
            },
        ]

        expected = (
            "# URL Reputation Batch Report\n"
            "\n"
            "## Results\n"
            "\n"
            "| Indicator | Type | Verdict | Risk | Domain | Error |\n"
            "| --- | --- | --- | --- | --- | --- |\n"
            "| `https://a.example` | `url` | `CLEAN` | `0/100` | `a.example` | - |\n"
            "| `https://b.example` | `url` | `HIGH_RISK` | `90/100` | `b.example` | - |\n"
            "| `https://c.example` | `url` | `ERROR` | `-` | `c.example` | boom |\n"
            "\n"
            "## Summary\n"
            "\n"
            "- Total: `3`\n"
            "- Worst verdict: `ERROR`\n"
            "- Counts by verdict:\n"
            "  - CLEAN: 1\n"
            "  - ERROR: 1\n"
            "  - HIGH_RISK: 1\n"
            "- Errors: `1`\n"
            "\n"
            "### Error details\n"
            "\n"
            "| Indicator | Error |\n"
            "| --- | --- |\n"
            "| `https://c.example` | boom |\n"
        )

        self.assertEqual(to_markdown_batch(results), expected)


if __name__ == "__main__":
    unittest.main()
