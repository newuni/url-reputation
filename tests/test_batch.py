"""
Tests for batch processing functionality.
"""

import unittest
from unittest.mock import patch, MagicMock
import tempfile
import os

from url_reputation.checker import check_urls_batch
from url_reputation.cli import check_urls_from_file, print_batch_results


class TestCheckUrlsBatch(unittest.TestCase):
    """Tests for batch URL checking."""
    
    @patch('url_reputation.checker.urlhaus')
    @patch('url_reputation.checker.phishtank')
    @patch('url_reputation.checker.dnsbl')
    def test_batch_returns_list(self, mock_dnsbl, mock_phish, mock_urlhaus):
        mock_urlhaus.check.return_value = {'listed': False}
        mock_phish.check.return_value = {'listed': False}
        mock_dnsbl.check.return_value = {'listed': False}
        
        urls = ['https://example1.com', 'https://example2.com']
        results = check_urls_batch(urls)
        
        self.assertIsInstance(results, list)
        self.assertEqual(len(results), 2)
    
    @patch('url_reputation.checker.urlhaus')
    @patch('url_reputation.checker.phishtank')
    @patch('url_reputation.checker.dnsbl')
    def test_batch_preserves_order(self, mock_dnsbl, mock_phish, mock_urlhaus):
        mock_urlhaus.check.return_value = {'listed': False}
        mock_phish.check.return_value = {'listed': False}
        mock_dnsbl.check.return_value = {'listed': False}
        
        urls = ['https://first.com', 'https://second.com', 'https://third.com']
        results = check_urls_batch(urls)
        
        self.assertEqual(results[0]['url'], 'https://first.com')
        self.assertEqual(results[1]['url'], 'https://second.com')
        self.assertEqual(results[2]['url'], 'https://third.com')
    
    def test_batch_empty_list(self):
        results = check_urls_batch([])
        self.assertEqual(results, [])
    
    @patch('url_reputation.checker.urlhaus')
    @patch('url_reputation.checker.phishtank')
    @patch('url_reputation.checker.dnsbl')
    def test_batch_each_result_has_structure(self, mock_dnsbl, mock_phish, mock_urlhaus):
        mock_urlhaus.check.return_value = {'listed': False}
        mock_phish.check.return_value = {'listed': False}
        mock_dnsbl.check.return_value = {'listed': False}
        
        urls = ['https://example.com']
        results = check_urls_batch(urls)
        
        result = results[0]
        self.assertIn('url', result)
        self.assertIn('domain', result)
        self.assertIn('risk_score', result)
        self.assertIn('verdict', result)
        self.assertIn('sources', result)


class TestCheckUrlsFromFile(unittest.TestCase):
    """Tests for file-based URL checking."""
    
    def test_reads_urls_from_file(self):
        with tempfile.NamedTemporaryFile(mode='w', suffix='.txt', delete=False) as f:
            f.write("https://example1.com\n")
            f.write("https://example2.com\n")
            f.write("https://example3.com\n")
            filepath = f.name
        
        try:
            with patch('url_reputation.cli.check_url_reputation') as mock_check:
                mock_check.return_value = {
                    'url': 'test',
                    'domain': 'test',
                    'risk_score': 0,
                    'verdict': 'CLEAN',
                    'sources': {}
                }
                
                results = check_urls_from_file(filepath)
                
                self.assertEqual(len(results), 3)
                self.assertEqual(mock_check.call_count, 3)
        finally:
            os.unlink(filepath)
    
    def test_skips_empty_lines(self):
        with tempfile.NamedTemporaryFile(mode='w', suffix='.txt', delete=False) as f:
            f.write("https://example1.com\n")
            f.write("\n")
            f.write("  \n")
            f.write("https://example2.com\n")
            filepath = f.name
        
        try:
            with patch('url_reputation.cli.check_url_reputation') as mock_check:
                mock_check.return_value = {
                    'url': 'test',
                    'domain': 'test',
                    'risk_score': 0,
                    'verdict': 'CLEAN',
                    'sources': {}
                }
                
                results = check_urls_from_file(filepath)
                
                self.assertEqual(len(results), 2)
        finally:
            os.unlink(filepath)
    
    def test_skips_comments(self):
        with tempfile.NamedTemporaryFile(mode='w', suffix='.txt', delete=False) as f:
            f.write("# This is a comment\n")
            f.write("https://example1.com\n")
            f.write("# Another comment\n")
            f.write("https://example2.com\n")
            filepath = f.name
        
        try:
            with patch('url_reputation.cli.check_url_reputation') as mock_check:
                mock_check.return_value = {
                    'url': 'test',
                    'domain': 'test',
                    'risk_score': 0,
                    'verdict': 'CLEAN',
                    'sources': {}
                }
                
                results = check_urls_from_file(filepath)
                
                self.assertEqual(len(results), 2)
        finally:
            os.unlink(filepath)
    
    def test_empty_file_returns_empty_list(self):
        with tempfile.NamedTemporaryFile(mode='w', suffix='.txt', delete=False) as f:
            f.write("")
            filepath = f.name
        
        try:
            results = check_urls_from_file(filepath)
            self.assertEqual(results, [])
        finally:
            os.unlink(filepath)


class TestPrintBatchResults(unittest.TestCase):
    """Tests for batch results output."""
    
    def test_prints_summary(self):
        from io import StringIO
        
        results = [
            {'url': 'https://clean.com', 'risk_score': 0, 'verdict': 'CLEAN'},
            {'url': 'https://risky.com', 'risk_score': 85, 'verdict': 'HIGH_RISK'},
        ]
        
        with patch('sys.stdout', new=StringIO()) as mock_stdout:
            print_batch_results(results)
            output = mock_stdout.getvalue()
        
        self.assertIn('Total URLs: 2', output)
        self.assertIn('CLEAN: 1', output)
        self.assertIn('HIGH_RISK: 1', output)
    
    def test_prints_error_results(self):
        from io import StringIO
        
        results = [
            {'url': 'https://failed.com', 'error': 'Network error', 'verdict': 'ERROR'},
        ]
        
        with patch('sys.stdout', new=StringIO()) as mock_stdout:
            print_batch_results(results)
            output = mock_stdout.getvalue()
        
        self.assertIn('ERROR', output)
        self.assertIn('Network error', output)


if __name__ == '__main__':
    unittest.main()
