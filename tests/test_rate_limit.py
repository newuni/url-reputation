import unittest
from datetime import datetime, timezone

from url_reputation.providers.base import Provider, ProviderContext
from url_reputation.rate_limit import RateLimitInfo, parse_rate_limit_info


class _DummyProvider(Provider):
    name = "dummy"

    def check(self, indicator: str, domain: str, ctx: ProviderContext) -> dict:  # pragma: no cover
        raise NotImplementedError


class TestRateLimitParsing(unittest.TestCase):
    def test_missing_headers_returns_none(self):
        now = datetime(2026, 2, 18, 12, 0, 0, tzinfo=timezone.utc)
        info = parse_rate_limit_info("x", {"Content-Type": "application/json"}, now=now)
        self.assertIsNone(info)

    def test_github_x_ratelimit_epoch_seconds(self):
        now = datetime(2026, 2, 18, 12, 0, 0, tzinfo=timezone.utc)
        reset_epoch = int(now.timestamp()) + 60
        headers = {
            "X-RateLimit-Limit": "5000",
            "X-RateLimit-Remaining": "4999",
            "X-RateLimit-Reset": str(reset_epoch),
        }

        info = parse_rate_limit_info("github", headers, now=now)
        self.assertIsInstance(info, RateLimitInfo)
        assert info is not None

        self.assertEqual(info.limit, 5000)
        self.assertEqual(info.remaining, 4999)
        self.assertEqual(info.reset_at, datetime.fromtimestamp(reset_epoch, tz=timezone.utc))
        self.assertEqual(info.reset_in_ms, 60_000)
        self.assertIsNone(info.retry_after_ms)
        self.assertIn("X-RateLimit-Reset", info.raw)

    def test_retry_after_seconds(self):
        now = datetime(2026, 2, 18, 12, 0, 0, tzinfo=timezone.utc)
        headers = {"Retry-After": "120"}

        info = parse_rate_limit_info("x", headers, now=now)
        assert info is not None

        self.assertEqual(info.retry_after_ms, 120_000)
        self.assertEqual(info.reset_at, datetime(2026, 2, 18, 12, 2, 0, tzinfo=timezone.utc))
        self.assertEqual(info.reset_in_ms, 120_000)
        self.assertIn("Retry-After", info.raw)

    def test_retry_after_http_date(self):
        now = datetime(2026, 2, 18, 12, 0, 0, tzinfo=timezone.utc)
        headers = {"Retry-After": "Wed, 18 Feb 2026 12:02:00 GMT"}

        info = parse_rate_limit_info("x", headers, now=now)
        assert info is not None

        self.assertEqual(info.retry_after_ms, 120_000)
        self.assertEqual(info.reset_at, datetime(2026, 2, 18, 12, 2, 0, tzinfo=timezone.utc))

    def test_bad_values_do_not_crash_and_capture_raw(self):
        now = datetime(2026, 2, 18, 12, 0, 0, tzinfo=timezone.utc)
        headers = {"Retry-After": "not-a-date"}

        info = parse_rate_limit_info("x", headers, now=now)
        assert info is not None

        self.assertIsNone(info.retry_after_ms)
        self.assertIsNone(info.reset_at)
        self.assertIn("Retry-After", info.raw)

    def test_provider_parse_rate_limit_from_payload_http_headers(self):
        p = _DummyProvider()
        payload = {
            "_http": {
                "status": 429,
                "headers": {"Retry-After": "1"},
            }
        }

        rl = p.parse_rate_limit(payload)
        self.assertIsInstance(rl, dict)
        assert isinstance(rl, dict)
        self.assertEqual(rl.get("provider"), "dummy")
        self.assertEqual(rl.get("retry_after_ms"), 1000)


if __name__ == "__main__":
    unittest.main()
