"""
Tests for individual source modules.
"""

import socket
import unittest
from unittest.mock import MagicMock, patch


class TestDNSBL(unittest.TestCase):
    """Tests for DNSBL source."""

    def test_extract_domain(self):
        from url_reputation.sources.dnsbl import _extract_domain

        self.assertEqual(_extract_domain("https://example.com/path"), "example.com")
        self.assertEqual(_extract_domain("http://test.com:8080"), "test.com")
        self.assertEqual(_extract_domain("example.com"), "example.com")

    def test_reverse_ip(self):
        from url_reputation.sources.dnsbl import _reverse_ip

        self.assertEqual(_reverse_ip("1.2.3.4"), "4.3.2.1")
        self.assertEqual(_reverse_ip("192.168.1.1"), "1.1.168.192")

    @patch("url_reputation.sources.dnsbl.socket.gethostbyname")
    def test_check_dnsbl_listed(self, mock_dns):
        from url_reputation.sources.dnsbl import _check_dnsbl

        mock_dns.return_value = "127.0.0.2"  # Listed response
        result = _check_dnsbl("evil.com", "dbl.spamhaus.org")
        self.assertTrue(result)

    @patch("url_reputation.sources.dnsbl.socket.gethostbyname")
    def test_check_dnsbl_not_listed(self, mock_dns):
        from url_reputation.sources.dnsbl import _check_dnsbl

        mock_dns.side_effect = socket.gaierror("NXDOMAIN")
        result = _check_dnsbl("clean.com", "dbl.spamhaus.org")
        self.assertFalse(result)

    @patch("url_reputation.sources.dnsbl._check_dnsbl")
    @patch("url_reputation.sources.dnsbl.socket.gethostbyname")
    def test_check_returns_structure(self, mock_resolve, mock_dnsbl):
        from url_reputation.sources.dnsbl import check

        mock_dnsbl.return_value = False
        mock_resolve.return_value = "93.184.216.34"

        result = check("https://example.com", "example.com", timeout=5)

        self.assertIn("listed", result)
        self.assertIn("details", result)
        self.assertIsInstance(result["listed"], bool)


class TestURLhaus(unittest.TestCase):
    """Tests for URLhaus source."""

    def test_get_domain(self):
        from url_reputation.sources.urlhaus import _get_domain

        self.assertEqual(_get_domain("https://evil.com/malware.exe"), "evil.com")
        self.assertEqual(_get_domain("http://test.org:8080/path"), "test.org:8080")

    @patch("url_reputation.sources.urlhaus._fetch_urlhaus_data")
    def test_check_url_listed(self, mock_fetch):
        from url_reputation.sources.urlhaus import check

        mock_fetch.return_value = {"urls": ["http://evil.com/malware.exe"], "domains": ["evil.com"]}

        result = check("http://evil.com/malware.exe", "evil.com")

        self.assertTrue(result["listed"])
        self.assertEqual(result["match_type"], "exact_url")

    @patch("url_reputation.sources.urlhaus._fetch_urlhaus_data")
    def test_check_domain_listed(self, mock_fetch):
        from url_reputation.sources.urlhaus import check

        mock_fetch.return_value = {"urls": ["http://evil.com/other.exe"], "domains": ["evil.com"]}

        result = check("http://evil.com/new-path", "evil.com")

        self.assertTrue(result["listed"])
        self.assertEqual(result["match_type"], "domain")

    @patch("url_reputation.sources.urlhaus._fetch_urlhaus_data")
    def test_check_not_listed(self, mock_fetch):
        from url_reputation.sources.urlhaus import check

        mock_fetch.return_value = {
            "urls": ["http://other.com/malware.exe"],
            "domains": ["other.com"],
        }

        result = check("https://clean.com", "clean.com")

        self.assertFalse(result["listed"])

    @patch("url_reputation.sources.urlhaus._fetch_urlhaus_data")
    def test_check_handles_error(self, mock_fetch):
        from url_reputation.sources.urlhaus import check

        mock_fetch.return_value = {"error": "Network timeout"}

        result = check("https://example.com", "example.com")

        self.assertIn("error", result)


class TestPhishtank(unittest.TestCase):
    """Tests for PhishTank/OpenPhish source."""

    @patch("url_reputation.sources.phishtank._fetch_phishtank_data")
    def test_check_url_listed(self, mock_fetch):
        from url_reputation.sources.phishtank import check

        mock_fetch.return_value = {
            "urls": ["http://phishing.com/login"],
            "domains": ["phishing.com"],
            "source": "openphish",
        }

        result = check("http://phishing.com/login", "phishing.com")

        self.assertTrue(result["listed"])
        self.assertEqual(result["match_type"], "exact_url")
        self.assertEqual(result["source"], "openphish")

    @patch("url_reputation.sources.phishtank._fetch_phishtank_data")
    def test_check_not_listed(self, mock_fetch):
        from url_reputation.sources.phishtank import check

        mock_fetch.return_value = {
            "urls": ["http://other-phish.com"],
            "domains": ["other-phish.com"],
            "source": "openphish",
        }

        result = check("https://legit.com", "legit.com")

        self.assertFalse(result["listed"])


class TestVirusTotal(unittest.TestCase):
    """Tests for VirusTotal source."""

    @patch.dict("os.environ", {}, clear=True)
    def test_check_without_api_key(self):
        from url_reputation.sources.virustotal import check

        result = check("https://example.com", "example.com")

        self.assertIn("error", result)
        self.assertIn("VIRUSTOTAL_API_KEY", result["error"])

    @patch.dict("os.environ", {"VIRUSTOTAL_API_KEY": "test-key"})
    @patch("url_reputation.sources.virustotal.urllib.request.urlopen")
    def test_check_with_api_key(self, mock_urlopen):
        import json

        from url_reputation.sources.virustotal import check

        mock_response = MagicMock()
        mock_response.read.return_value = json.dumps(
            {
                "data": {
                    "attributes": {
                        "last_analysis_stats": {
                            "malicious": 5,
                            "suspicious": 2,
                            "harmless": 60,
                            "undetected": 3,
                        },
                        "reputation": -10,
                        "categories": {},
                    }
                }
            }
        ).encode()
        mock_response.__enter__ = MagicMock(return_value=mock_response)
        mock_response.__exit__ = MagicMock(return_value=False)
        mock_urlopen.return_value = mock_response

        result = check("https://example.com", "example.com")

        self.assertEqual(result["detected"], 7)  # 5 + 2
        self.assertEqual(result["total"], 70)
        self.assertEqual(result["malicious"], 5)


class TestURLScan(unittest.TestCase):
    """Tests for URLScan.io source."""

    @patch.dict("os.environ", {}, clear=True)
    def test_check_without_api_key(self):
        from url_reputation.sources.urlscan import check

        result = check("https://example.com", "example.com")

        self.assertIn("error", result)
        self.assertIn("URLSCAN_API_KEY", result["error"])

    @patch.dict("os.environ", {"URLSCAN_API_KEY": "k"})
    @patch("url_reputation.sources.urlscan._search_url")
    def test_check_found_path(self, mock_search):
        from url_reputation.sources.urlscan import check

        mock_search.return_value = {"found": True, "score": 1}
        result = check("https://example.com", "example.com")
        self.assertTrue(result["found"])

    @patch.dict("os.environ", {"URLSCAN_API_KEY": "k"})
    @patch("url_reputation.sources.urlscan.urllib.request.urlopen")
    def test_submit_scan(self, mock_urlopen):
        import json

        from url_reputation.sources.urlscan import _submit_scan

        mock_response = MagicMock()
        mock_response.read.return_value = json.dumps(
            {"uuid": "u-1", "result": "https://urlscan.io/result/u-1"}
        ).encode()
        mock_response.__enter__ = MagicMock(return_value=mock_response)
        mock_response.__exit__ = MagicMock(return_value=False)
        mock_urlopen.return_value = mock_response

        result = _submit_scan("https://example.com", "k")
        self.assertTrue(result["submitted"])
        self.assertEqual(result["scan_uuid"], "u-1")


class TestThreatFox(unittest.TestCase):
    """Tests for ThreatFox source."""

    @patch.dict("os.environ", {}, clear=True)
    def test_check_without_api_key(self):
        from url_reputation.sources.threatfox import check

        result = check("https://example.com", "example.com")

        self.assertIn("error", result)
        self.assertIn("THREATFOX_API_KEY", result["error"])

    @patch.dict("os.environ", {"THREATFOX_API_KEY": "test-key"})
    @patch("url_reputation.sources.threatfox.urllib.request.urlopen")
    def test_check_no_result(self, mock_urlopen):
        import json

        from url_reputation.sources.threatfox import check

        mock_response = MagicMock()
        mock_response.read.return_value = json.dumps({"query_status": "no_result"}).encode()
        mock_response.__enter__ = MagicMock(return_value=mock_response)
        mock_response.__exit__ = MagicMock(return_value=False)
        mock_urlopen.return_value = mock_response

        result = check("https://example.com", "example.com")

        self.assertEqual(result["listed"], False)

    @patch("url_reputation.sources.threatfox.urllib.request.urlopen")
    def test_check_hash(self, mock_urlopen):
        import json

        from url_reputation.sources.threatfox import check_hash

        mock_response = MagicMock()
        mock_response.read.return_value = json.dumps(
            {"query_status": "ok", "data": [{"x": 1}]}
        ).encode()
        mock_response.__enter__ = MagicMock(return_value=mock_response)
        mock_response.__exit__ = MagicMock(return_value=False)
        mock_urlopen.return_value = mock_response

        result = check_hash("abcd", timeout=3)

        self.assertTrue(result["found"])
        self.assertEqual(len(result["data"]), 1)


class TestAbuseIPDB(unittest.TestCase):
    @patch.dict("os.environ", {}, clear=True)
    def test_check_without_api_key(self):
        from url_reputation.sources.abuseipdb import check

        result = check("https://example.com", "example.com")
        self.assertIn("error", result)

    @patch.dict("os.environ", {"ABUSEIPDB_API_KEY": "k"})
    @patch("url_reputation.sources.abuseipdb.socket.gethostbyname")
    @patch("url_reputation.sources.abuseipdb.urllib.request.urlopen")
    def test_check_success(self, mock_urlopen, mock_resolve):
        import json

        from url_reputation.sources.abuseipdb import check

        mock_resolve.return_value = "1.2.3.4"
        mock_response = MagicMock()
        mock_response.read.return_value = json.dumps(
            {"data": {"abuseConfidenceScore": 42, "totalReports": 5}}
        ).encode()
        mock_response.__enter__ = MagicMock(return_value=mock_response)
        mock_response.__exit__ = MagicMock(return_value=False)
        mock_urlopen.return_value = mock_response

        result = check("https://x", "example.com")
        self.assertEqual(result["ip"], "1.2.3.4")
        self.assertEqual(result["abuse_score"], 42)

    @patch.dict("os.environ", {"ABUSEIPDB_API_KEY": "k"})
    @patch("url_reputation.sources.abuseipdb.socket.gethostbyname")
    @patch("url_reputation.sources.abuseipdb.urllib.request.urlopen")
    def test_check_http_401(self, mock_urlopen, mock_resolve):
        import urllib.error

        from url_reputation.sources.abuseipdb import check

        mock_resolve.return_value = "1.2.3.4"
        mock_urlopen.side_effect = urllib.error.HTTPError(
            url="x", code=401, msg="unauthorized", hdrs=None, fp=None
        )

        result = check("https://x", "example.com")
        self.assertIn("Invalid API key", result["error"])


class TestAlienVaultOTX(unittest.TestCase):
    @patch("url_reputation.sources.alienvault_otx.urllib.request.urlopen")
    def test_check_ok(self, mock_urlopen):
        import json

        from url_reputation.sources.alienvault_otx import check

        payload = {
            "pulse_info": {"count": 1, "pulses": [{"name": "x", "tags": ["a"]}]},
            "validation": [{"source": "alexa", "message": "Rank #1,234"}],
        }
        mock_response = MagicMock()
        mock_response.read.return_value = json.dumps(payload).encode()
        mock_response.__enter__ = MagicMock(return_value=mock_response)
        mock_response.__exit__ = MagicMock(return_value=False)
        mock_urlopen.return_value = mock_response

        result = check("https://x", "example.com")
        self.assertTrue(result["has_pulses"])
        self.assertEqual(result["alexa_rank"], 1234)

    @patch("url_reputation.sources.alienvault_otx.urllib.request.urlopen")
    def test_check_url_indicators_exception(self, mock_urlopen):
        from url_reputation.sources.alienvault_otx import check_url_indicators

        mock_urlopen.side_effect = RuntimeError("boom")
        result = check_url_indicators("https://x", "example.com")
        self.assertEqual(result, {})


class TestIPQualityScore(unittest.TestCase):
    @patch.dict("os.environ", {}, clear=True)
    def test_check_without_api_key(self):
        from url_reputation.sources.ipqualityscore import check

        result = check("https://x", "example.com")
        self.assertIn("error", result)

    @patch.dict("os.environ", {"IPQUALITYSCORE_API_KEY": "k"})
    @patch("url_reputation.sources.ipqualityscore.urllib.request.urlopen")
    def test_check_success(self, mock_urlopen):
        import json

        from url_reputation.sources.ipqualityscore import check

        mock_response = MagicMock()
        mock_response.read.return_value = json.dumps({"success": True, "risk_score": 12}).encode()
        mock_response.__enter__ = MagicMock(return_value=mock_response)
        mock_response.__exit__ = MagicMock(return_value=False)
        mock_urlopen.return_value = mock_response

        result = check("https://x", "example.com")
        self.assertEqual(result["risk_score"], 12)

    @patch.dict("os.environ", {"IPQUALITYSCORE_API_KEY": "k"})
    @patch("url_reputation.sources.ipqualityscore.urllib.request.urlopen")
    def test_check_api_error_payload(self, mock_urlopen):
        import json

        from url_reputation.sources.ipqualityscore import check

        mock_response = MagicMock()
        mock_response.read.return_value = json.dumps(
            {"success": False, "message": "bad request"}
        ).encode()
        mock_response.__enter__ = MagicMock(return_value=mock_response)
        mock_response.__exit__ = MagicMock(return_value=False)
        mock_urlopen.return_value = mock_response

        result = check("https://x", "example.com")
        self.assertIn("bad request", result["error"])


class TestSafeBrowsing(unittest.TestCase):
    """Tests for Google Safe Browsing source."""

    @patch.dict("os.environ", {}, clear=True)
    def test_check_without_api_key(self):
        from url_reputation.sources.safebrowsing import check

        result = check("https://example.com", "example.com")

        self.assertIn("error", result)
        self.assertIn("GOOGLE_SAFEBROWSING_API_KEY", result["error"])

    @patch.dict("os.environ", {"GOOGLE_SAFEBROWSING_API_KEY": "test-key"})
    @patch("url_reputation.sources.safebrowsing.urllib.request.urlopen")
    def test_check_clean_url(self, mock_urlopen):
        import json

        from url_reputation.sources.safebrowsing import check

        mock_response = MagicMock()
        mock_response.read.return_value = json.dumps({}).encode()
        mock_response.__enter__ = MagicMock(return_value=mock_response)
        mock_response.__exit__ = MagicMock(return_value=False)
        mock_urlopen.return_value = mock_response

        result = check("https://example.com", "example.com")

        self.assertEqual(result["threats"], [])

    @patch.dict("os.environ", {"GOOGLE_SAFEBROWSING_API_KEY": "test-key"})
    @patch("url_reputation.sources.safebrowsing.urllib.request.urlopen")
    def test_check_malicious_url(self, mock_urlopen):
        import json

        from url_reputation.sources.safebrowsing import check

        mock_response = MagicMock()
        mock_response.read.return_value = json.dumps(
            {
                "matches": [
                    {
                        "threatType": "MALWARE",
                        "platformType": "ANY_PLATFORM",
                        "cacheDuration": "300s",
                    }
                ]
            }
        ).encode()
        mock_response.__enter__ = MagicMock(return_value=mock_response)
        mock_response.__exit__ = MagicMock(return_value=False)
        mock_urlopen.return_value = mock_response

        result = check("https://malware.com", "malware.com")

        self.assertEqual(len(result["threats"]), 1)
        self.assertEqual(result["threats"][0]["type"], "MALWARE")


class TestAbuseIPDBLegacy(unittest.TestCase):
    """Tests for AbuseIPDB source (legacy/basic cases)."""

    @patch.dict("os.environ", {}, clear=True)
    def test_check_without_api_key(self):
        from url_reputation.sources.abuseipdb import check

        result = check("https://example.com", "example.com")

        self.assertIn("error", result)
        self.assertIn("ABUSEIPDB_API_KEY", result["error"])

    @patch.dict("os.environ", {"ABUSEIPDB_API_KEY": "test-key"})
    @patch("url_reputation.sources.abuseipdb.socket.gethostbyname")
    def test_check_unresolvable_domain(self, mock_dns):
        from url_reputation.sources.abuseipdb import check

        mock_dns.side_effect = socket.gaierror("NXDOMAIN")

        result = check("https://nonexistent.invalid", "nonexistent.invalid")

        self.assertIn("error", result)
        self.assertIn("Could not resolve", result["error"])


if __name__ == "__main__":
    unittest.main()
