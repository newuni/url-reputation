import os
import tempfile
import unittest
from unittest.mock import MagicMock, patch


class TestPhishTankFeed(unittest.TestCase):
    def test_cache_roundtrip(self):
        import url_reputation.sources.phishtank as ph

        with tempfile.TemporaryDirectory() as td:
            cache_path = os.path.join(td, "phishtank.json")
            with patch.object(ph, "CACHE_FILE", cache_path):
                payload = {"urls": ["https://a"], "domains": ["a"]}
                ph._save_cache(payload)
                loaded, mtime = ph._load_cache()
                self.assertEqual(loaded, payload)
                self.assertGreater(mtime, 0)

    @patch("url_reputation.sources.phishtank.urllib.request.urlopen")
    def test_fetch_parses_openphish(self, mock_urlopen):
        import url_reputation.sources.phishtank as ph

        mock_response = MagicMock()
        mock_response.read.return_value = b"https://a.test/login\nhttps://b.test/x\n"
        mock_response.__enter__ = MagicMock(return_value=mock_response)
        mock_response.__exit__ = MagicMock(return_value=False)
        mock_urlopen.return_value = mock_response

        with patch.object(ph, "_load_cache", return_value=(None, 0.0)):
            data = ph._fetch_phishtank_data(timeout=2)

        self.assertEqual(data["source"], "openphish")
        self.assertIn("https://a.test/login", data["urls"])
        self.assertIn("a.test", data["domains"])

    @patch("url_reputation.sources.phishtank.urllib.request.urlopen")
    def test_fetch_handles_error(self, mock_urlopen):
        import url_reputation.sources.phishtank as ph

        mock_urlopen.side_effect = RuntimeError("network")
        with patch.object(ph, "_load_cache", return_value=(None, 0.0)):
            data = ph._fetch_phishtank_data(timeout=2)
        self.assertIn("error", data)


class TestURLhausFeed(unittest.TestCase):
    def test_cache_roundtrip(self):
        import url_reputation.sources.urlhaus as uh

        with tempfile.TemporaryDirectory() as td:
            cache_path = os.path.join(td, "urlhaus.json")
            with patch.object(uh, "CACHE_FILE", cache_path):
                payload = {"urls": ["https://a"], "domains": ["a"]}
                uh._save_cache(payload)
                loaded, mtime = uh._load_cache()
                self.assertEqual(loaded, payload)
                self.assertGreater(mtime, 0)

    @patch("url_reputation.sources.urlhaus.urllib.request.urlopen")
    def test_fetch_parses_text_online(self, mock_urlopen):
        import url_reputation.sources.urlhaus as uh

        first = MagicMock()
        first.__enter__ = MagicMock(return_value=first)
        first.__exit__ = MagicMock(return_value=False)
        first.read.return_value = b""

        second = MagicMock()
        second.__enter__ = MagicMock(return_value=second)
        second.__exit__ = MagicMock(return_value=False)
        second.read.return_value = b"#comment\nhttps://evil.test/a\n"

        mock_urlopen.side_effect = [first, second]

        with patch.object(uh, "_load_cache", return_value=(None, 0.0)):
            data = uh._fetch_urlhaus_data(timeout=2)

        self.assertIn("https://evil.test/a", data["urls"])
        self.assertIn("evil.test", data["domains"])

    @patch("url_reputation.sources.urlhaus.urllib.request.urlopen")
    def test_fetch_handles_error(self, mock_urlopen):
        import url_reputation.sources.urlhaus as uh

        mock_urlopen.side_effect = RuntimeError("network")
        with patch.object(uh, "_load_cache", return_value=(None, 0.0)):
            data = uh._fetch_urlhaus_data(timeout=2)
        self.assertIn("error", data)


if __name__ == "__main__":
    unittest.main()
