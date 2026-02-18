import tempfile
import unittest

from url_reputation.cache import Cache, make_cache_key
from url_reputation.checker import check_url_reputation


class TestCache(unittest.TestCase):
    def test_cache_set_get(self):
        with tempfile.TemporaryDirectory() as d:
            path = f"{d}/cache.sqlite"
            c = Cache(path)
            key = "k"
            c.set(key, {"a": 1})
            self.assertEqual(c.get(key, ttl_seconds=60), {"a": 1})

    def test_check_url_reputation_uses_cache(self):
        with tempfile.TemporaryDirectory() as d:
            path = f"{d}/cache.sqlite"

            # First call populates cache
            r1 = check_url_reputation(
                "https://example.com",
                sources=["urlhaus"],
                timeout=1,
                cache_path=path,
                cache_ttl_seconds=3600,
            )

            # Second call should hit cache (same key)
            r2 = check_url_reputation(
                "https://example.com",
                sources=["urlhaus"],
                timeout=1,
                cache_path=path,
                cache_ttl_seconds=3600,
            )

            self.assertEqual(r1["schema_version"], "1")
            self.assertEqual(r2, r1)

    def test_cache_key_stable(self):
        k1 = make_cache_key(
            schema_version="1",
            indicator_canonical="https://example.com",
            providers=["b", "a"],
        )
        k2 = make_cache_key(
            schema_version="1",
            indicator_canonical="https://example.com",
            providers=["a", "b"],
        )
        self.assertEqual(k1, k2)


if __name__ == "__main__":
    unittest.main()
