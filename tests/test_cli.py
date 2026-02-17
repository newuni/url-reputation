"""
Tests for the CLI module.
"""

import json
import unittest
from io import StringIO
from unittest.mock import patch

from url_reputation.cli import main, print_human_readable


class TestPrintHumanReadable(unittest.TestCase):
    """Tests for human-readable output formatting."""
    
    def test_clean_verdict_output(self):
        result = {
            'url': 'https://example.com',
            'domain': 'example.com',
            'risk_score': 0,
            'verdict': 'CLEAN',
            'checked_at': '2026-01-20T19:00:00+00:00',
            'sources': [
                {'name': 'urlhaus', 'status': 'ok', 'raw': {'listed': False}},
                {'name': 'dnsbl', 'status': 'ok', 'raw': {'listed': False}},
            ]
        }
        
        with patch('sys.stdout', new=StringIO()) as mock_stdout:
            print_human_readable(result)
            output = mock_stdout.getvalue()
        
        self.assertIn('example.com', output)
        self.assertIn('CLEAN', output)
        self.assertIn('0/100', output)
        self.assertIn('✅', output)
    
    def test_high_risk_verdict_output(self):
        result = {
            'url': 'https://evil.com',
            'domain': 'evil.com',
            'risk_score': 85,
            'verdict': 'HIGH_RISK',
            'checked_at': '2026-01-20T19:00:00+00:00',
            'sources': [
                {'name': 'urlhaus', 'status': 'ok', 'raw': {'listed': True, 'threat_type': 'malware'}},
            ]
        }
        
        with patch('sys.stdout', new=StringIO()) as mock_stdout:
            print_human_readable(result)
            output = mock_stdout.getvalue()
        
        self.assertIn('HIGH_RISK', output)
        self.assertIn('🔴', output)
        self.assertIn('Listed', output)
    
    def test_error_source_output(self):
        result = {
            'url': 'https://example.com',
            'domain': 'example.com',
            'risk_score': 0,
            'verdict': 'CLEAN',
            'checked_at': '2026-01-20T19:00:00+00:00',
            'sources': [
                {'name': 'urlhaus', 'status': 'error', 'raw': {}, 'error': 'Connection timeout'},
            ]
        }
        
        with patch('sys.stdout', new=StringIO()) as mock_stdout:
            print_human_readable(result)
            output = mock_stdout.getvalue()
        
        self.assertIn('Error', output)
        self.assertIn('Connection timeout', output)
    
    def test_virustotal_detection_output(self):
        result = {
            'url': 'https://example.com',
            'domain': 'example.com',
            'risk_score': 25,
            'verdict': 'LOW_RISK',
            'checked_at': '2026-01-20T19:00:00+00:00',
            'sources': [
                {'name': 'virustotal', 'status': 'ok', 'raw': {'detected': 5, 'total': 70}},
            ]
        }
        
        with patch('sys.stdout', new=StringIO()) as mock_stdout:
            print_human_readable(result)
            output = mock_stdout.getvalue()
        
        self.assertIn('5/70', output)
        self.assertIn('engines detected', output)


class TestCLIMain(unittest.TestCase):
    """Tests for the main CLI entry point."""
    
    @patch('url_reputation.cli.check_url_reputation')
    def test_basic_call(self, mock_check):
        mock_check.return_value = {
            'schema_version': '1',
            'indicator': {
                'input': 'https://example.com',
                'type': 'url',
                'canonical': 'https://example.com',
                'domain': 'example.com',
            },
            'url': 'https://example.com',
            'domain': 'example.com',
            'risk_score': 0,
            'verdict': 'CLEAN',
            'checked_at': '2026-01-20T19:00:00+00:00',
            'sources': []
        }
        
        with patch('sys.argv', ['url-reputation', 'https://example.com']):
            with patch('sys.stdout', new=StringIO()):
                with self.assertRaises(SystemExit):
                    main()
        
        mock_check.assert_called_once()
        call_args = mock_check.call_args
        self.assertEqual(call_args[0][0], 'https://example.com')
    
    @patch('url_reputation.cli.check_url_reputation')
    def test_json_output(self, mock_check):
        expected_result = {
            'schema_version': '1',
            'indicator': {
                'input': 'https://example.com',
                'type': 'url',
                'canonical': 'https://example.com',
                'domain': 'example.com',
            },
            'url': 'https://example.com',
            'domain': 'example.com',
            'risk_score': 0,
            'verdict': 'CLEAN',
            'checked_at': '2026-01-20T19:00:00+00:00',
            'sources': [
                {'name': 'urlhaus', 'status': 'ok', 'raw': {'listed': False}},
            ]
        }
        mock_check.return_value = expected_result
        
        with patch('sys.argv', ['url-reputation', 'https://example.com', '--json']):
            with patch('sys.stdout', new=StringIO()) as mock_stdout:
                with self.assertRaises(SystemExit):
                    main()
                output = mock_stdout.getvalue()
        
        parsed = json.loads(output)
        self.assertEqual(parsed['url'], 'https://example.com')
        self.assertEqual(parsed['verdict'], 'CLEAN')
    
    @patch('url_reputation.cli.check_url_reputation')
    def test_specific_sources(self, mock_check):
        mock_check.return_value = {
            'schema_version': '1',
            'indicator': {
                'input': 'https://example.com',
                'type': 'url',
                'canonical': 'https://example.com',
                'domain': 'example.com',
            },
            'url': 'https://example.com',
            'domain': 'example.com',
            'risk_score': 0,
            'verdict': 'CLEAN',
            'checked_at': '2026-01-20T19:00:00+00:00',
            'sources': []
        }
        
        with patch('sys.argv', ['url-reputation', 'https://example.com', '-s', 'urlhaus,dnsbl']):
            with patch('sys.stdout', new=StringIO()):
                with self.assertRaises(SystemExit):
                    main()
        
        call_args = mock_check.call_args
        self.assertEqual(call_args[0][1], ['urlhaus', 'dnsbl'])
    
    @patch('url_reputation.cli.check_url_reputation')
    def test_custom_timeout(self, mock_check):
        mock_check.return_value = {
            'schema_version': '1',
            'indicator': {
                'input': 'https://example.com',
                'type': 'url',
                'canonical': 'https://example.com',
                'domain': 'example.com',
            },
            'url': 'https://example.com',
            'domain': 'example.com',
            'risk_score': 0,
            'verdict': 'CLEAN',
            'checked_at': '2026-01-20T19:00:00+00:00',
            'sources': []
        }
        
        with patch('sys.argv', ['url-reputation', 'https://example.com', '-t', '60']):
            with patch('sys.stdout', new=StringIO()):
                with self.assertRaises(SystemExit):
                    main()
        
        call_args = mock_check.call_args
        self.assertEqual(call_args[0][2], 60)


if __name__ == '__main__':
    unittest.main()
