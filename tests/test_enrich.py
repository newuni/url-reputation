"""
Tests for DNS and Whois enrichment.
"""

import unittest
from unittest.mock import patch, MagicMock
import socket

from url_reputation.enrich import enrich_dns, enrich_whois, enrich


class TestEnrichDNS(unittest.TestCase):
    """Tests for DNS enrichment."""
    
    @patch('url_reputation.enrich.socket.getaddrinfo')
    def test_basic_a_record(self, mock_getaddrinfo):
        # Mock A record response
        mock_getaddrinfo.return_value = [
            (socket.AF_INET, socket.SOCK_STREAM, 6, '', ('93.184.216.34', 0))
        ]
        
        result = enrich_dns('example.com')
        
        self.assertIn('a_records', result)
        self.assertEqual(result['a_records'], ['93.184.216.34'])
    
    @patch('url_reputation.enrich.socket.getaddrinfo')
    def test_multiple_a_records(self, mock_getaddrinfo):
        mock_getaddrinfo.return_value = [
            (socket.AF_INET, socket.SOCK_STREAM, 6, '', ('1.1.1.1', 0)),
            (socket.AF_INET, socket.SOCK_STREAM, 6, '', ('2.2.2.2', 0)),
        ]
        
        result = enrich_dns('example.com')
        
        self.assertIn('1.1.1.1', result['a_records'])
        self.assertIn('2.2.2.2', result['a_records'])
    
    @patch('url_reputation.enrich.socket.getaddrinfo')
    def test_no_records(self, mock_getaddrinfo):
        mock_getaddrinfo.side_effect = socket.gaierror('No address')
        
        result = enrich_dns('nonexistent.invalid')
        
        self.assertEqual(result['a_records'], [])
    
    def test_returns_expected_structure(self):
        result = enrich_dns('example.com', timeout=2)
        
        self.assertIn('a_records', result)
        self.assertIn('aaaa_records', result)
        self.assertIn('mx_records', result)
        self.assertIn('ns_records', result)
        self.assertIn('txt_records', result)
        self.assertIsInstance(result['a_records'], list)


class TestEnrichWhois(unittest.TestCase):
    """Tests for Whois enrichment."""
    
    def test_returns_expected_structure(self):
        result = enrich_whois('example.com', timeout=5)
        
        self.assertIn('creation_date', result)
        self.assertIn('expiration_date', result)
        self.assertIn('registrar', result)
        self.assertIn('domain_age_days', result)
        self.assertIn('is_new_domain', result)
    
    @patch('url_reputation.enrich.subprocess.run')
    def test_whois_cli_fallback(self, mock_run):
        mock_run.return_value = MagicMock(
            returncode=0,
            stdout='''
Domain Name: EXAMPLE.COM
Creation Date: 2020-01-15T00:00:00Z
Registrar: Test Registrar Inc.
Registrant Country: US
'''
        )
        
        # Force CLI fallback by not having python-whois
        with patch.dict('sys.modules', {'whois': None}):
            result = enrich_whois('example.com')
        
        # Should have parsed some data
        self.assertIn('creation_date', result)
    
    @patch('url_reputation.enrich.subprocess.run')
    def test_whois_cli_not_found(self, mock_run):
        mock_run.side_effect = FileNotFoundError()
        
        with patch.dict('sys.modules', {'whois': None}):
            result = enrich_whois('example.com')
        
        self.assertIn('error', result)
        self.assertIn('not available', result['error'])


class TestEnrich(unittest.TestCase):
    """Tests for combined enrichment."""
    
    @patch('url_reputation.enrich.enrich_dns')
    @patch('url_reputation.enrich.enrich_whois')
    def test_enrich_all(self, mock_whois, mock_dns):
        mock_dns.return_value = {
            'a_records': ['1.2.3.4'],
            'mx_records': [],
            'has_spf': False,
        }
        mock_whois.return_value = {
            'creation_date': '2020-01-01',
            'domain_age_days': 1000,
            'is_new_domain': False,
        }
        
        result = enrich('example.com')
        
        self.assertIn('dns', result)
        self.assertIn('whois', result)
        mock_dns.assert_called_once()
        mock_whois.assert_called_once()
    
    @patch('url_reputation.enrich.enrich_dns')
    @patch('url_reputation.enrich.enrich_whois')
    def test_enrich_dns_only(self, mock_whois, mock_dns):
        mock_dns.return_value = {'a_records': ['1.2.3.4']}
        
        result = enrich('example.com', types=['dns'])
        
        self.assertIn('dns', result)
        self.assertNotIn('whois', result)
        mock_dns.assert_called_once()
        mock_whois.assert_not_called()
    
    @patch('url_reputation.enrich.enrich_dns')
    @patch('url_reputation.enrich.enrich_whois')
    def test_enrich_whois_only(self, mock_whois, mock_dns):
        mock_whois.return_value = {'creation_date': '2020-01-01'}
        
        result = enrich('example.com', types=['whois'])
        
        self.assertIn('whois', result)
        self.assertNotIn('dns', result)
        mock_whois.assert_called_once()
        mock_dns.assert_not_called()
    
    @patch('url_reputation.enrich.enrich_dns')
    @patch('url_reputation.enrich.enrich_whois')
    def test_risk_indicators_new_domain(self, mock_whois, mock_dns):
        mock_dns.return_value = {
            'a_records': ['1.2.3.4'],
            'mx_records': [{'host': 'mail.example.com'}],
            'has_spf': True,
        }
        mock_whois.return_value = {
            'creation_date': '2026-01-01',
            'domain_age_days': 5,
            'is_new_domain': True,
        }
        
        result = enrich('example.com')
        
        self.assertIn('risk_indicators', result)
        self.assertTrue(any('7 days' in i for i in result['risk_indicators']))
    
    @patch('url_reputation.enrich.enrich_dns')
    @patch('url_reputation.enrich.enrich_whois')
    def test_risk_indicators_no_spf(self, mock_whois, mock_dns):
        mock_dns.return_value = {
            'a_records': ['1.2.3.4'],
            'mx_records': [{'host': 'mail.example.com'}],
            'has_spf': False,
        }
        mock_whois.return_value = {
            'domain_age_days': 1000,
            'is_new_domain': False,
        }
        
        result = enrich('example.com')
        
        self.assertIn('risk_indicators', result)
        self.assertTrue(any('SPF' in i for i in result['risk_indicators']))
    
    @patch('url_reputation.enrich.enrich_dns')
    @patch('url_reputation.enrich.enrich_whois')
    def test_no_risk_indicators_when_clean(self, mock_whois, mock_dns):
        mock_dns.return_value = {
            'a_records': ['1.2.3.4'],
            'mx_records': [{'host': 'mail.example.com'}],
            'has_spf': True,
        }
        mock_whois.return_value = {
            'domain_age_days': 1000,
            'is_new_domain': False,
        }
        
        result = enrich('example.com')
        
        # Should not have risk_indicators key or it should be empty
        self.assertFalse(result.get('risk_indicators'))


if __name__ == '__main__':
    unittest.main()
