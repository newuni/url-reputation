"""
Tests for batch processing functionality.
"""

import os
import tempfile
import time
import unittest
from unittest.mock import patch

from url_reputation.checker import check_urls_batch
from url_reputation.cli import check_urls_from_file, print_batch_results, run_batch


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


class TestRunBatch(unittest.TestCase):
    """Tests for streaming batch runner (offline, mocked)."""

    @patch('url_reputation.cli.check_url_reputation')
    def test_run_batch_streams_as_completed_by_default(self, mock_check):
        def fake_check(url, *_args, **_kwargs):
            # Make the first URL slow so it should not be yielded first when streaming.
            if url.endswith('/slow'):
                time.sleep(0.05)
            return {'url': url, 'verdict': 'CLEAN', 'risk_score': 0, 'domain': 'example.com', 'sources': []}

        mock_check.side_effect = fake_check

        urls = ['https://example.com/slow', 'https://example.com/fast1', 'https://example.com/fast2']
        results = list(
            run_batch(
                iter(urls),
                sources=None,
                timeout=1,
                max_workers=3,
                cache=None,
                cache_ttl='24h',
                no_cache=True,
            )
        )

        self.assertEqual(len(results), 3)
        self.assertNotEqual(results[0]['url'], urls[0])

    @patch('url_reputation.cli.check_url_reputation')
    def test_run_batch_preserve_order(self, mock_check):
        def fake_check(url, *_args, **_kwargs):
            if url.endswith('/slow'):
                time.sleep(0.05)
            return {'url': url, 'verdict': 'CLEAN', 'risk_score': 0, 'domain': 'example.com', 'sources': []}

        mock_check.side_effect = fake_check

        urls = ['https://example.com/slow', 'https://example.com/fast1', 'https://example.com/fast2']
        results = list(
            run_batch(
                iter(urls),
                sources=None,
                timeout=1,
                max_workers=3,
                cache=None,
                cache_ttl='24h',
                no_cache=True,
                preserve_order=True,
            )
        )

        self.assertEqual([r['url'] for r in results], urls)

    @patch('url_reputation.cli.check_url_reputation')
    def test_run_batch_max_requests_caps_work(self, mock_check):
        mock_check.return_value = {'url': 'x', 'verdict': 'CLEAN', 'risk_score': 0, 'domain': 'example.com', 'sources': []}

        urls = [f'https://example.com/{i}' for i in range(5)]
        results = list(
            run_batch(
                iter(urls),
                sources=None,
                timeout=1,
                max_workers=2,
                cache=None,
                cache_ttl='24h',
                no_cache=True,
                max_requests=2,
            )
        )

        self.assertEqual(len(results), 2)
        self.assertEqual(mock_check.call_count, 2)

    @patch('url_reputation.cli.check_url_reputation')
    def test_run_batch_budget_seconds_caps_submissions(self, mock_check):
        mock_check.return_value = {'url': 'x', 'verdict': 'CLEAN', 'risk_score': 0, 'domain': 'example.com', 'sources': []}

        def slow_iter():
            yield 'https://example.com/1'
            time.sleep(0.05)  # ensure budget expires before the next item is submitted
            yield 'https://example.com/2'

        results = list(
            run_batch(
                slow_iter(),
                sources=None,
                timeout=1,
                max_workers=2,
                cache=None,
                cache_ttl='24h',
                no_cache=True,
                budget_seconds=0.01,
            )
        )

        self.assertEqual(len(results), 1)
        self.assertEqual(mock_check.call_count, 1)


if __name__ == '__main__':
    unittest.main()
