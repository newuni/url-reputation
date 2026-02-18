import unittest
from io import StringIO
from unittest.mock import patch

from url_reputation.cli import main


class TestExitCodes(unittest.TestCase):
    @patch("url_reputation.cli.check_url_reputation")
    def test_fail_on_low_risk(self, mock_check):
        mock_check.return_value = {
            "schema_version": "1",
            "indicator": {
                "input": "https://x",
                "type": "url",
                "canonical": "https://x",
                "domain": "x",
            },
            "url": "https://x",
            "domain": "x",
            "risk_score": 30,
            "verdict": "LOW_RISK",
            "checked_at": "2026-01-20T19:00:00+00:00",
            "sources": [],
        }

        with patch(
            "sys.argv", ["url-reputation", "https://x", "--format", "json", "--fail-on", "LOW_RISK"]
        ), patch("sys.stdout", new=StringIO()), self.assertRaises(SystemExit) as ctx:
            main()

        self.assertEqual(ctx.exception.code, 1)

    @patch("url_reputation.cli.check_url_reputation")
    def test_no_fail_on_defaults_zero(self, mock_check):
        mock_check.return_value = {
            "schema_version": "1",
            "indicator": {
                "input": "https://x",
                "type": "url",
                "canonical": "https://x",
                "domain": "x",
            },
            "url": "https://x",
            "domain": "x",
            "risk_score": 85,
            "verdict": "HIGH_RISK",
            "checked_at": "2026-01-20T19:00:00+00:00",
            "sources": [],
        }

        with patch("sys.argv", ["url-reputation", "https://x", "--format", "json"]), patch(
            "sys.stdout", new=StringIO()
        ), self.assertRaises(SystemExit) as ctx:
            main()

        self.assertEqual(ctx.exception.code, 0)


if __name__ == "__main__":
    unittest.main()
