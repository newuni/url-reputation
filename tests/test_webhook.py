"""
Tests for webhook functionality.
"""

import unittest
from unittest.mock import patch, MagicMock
import json
import time
import hmac
import hashlib

from url_reputation.webhook import (
    send_webhook,
    notify_on_risk,
    verify_signature,
    _generate_signature,
)


class TestGenerateSignature(unittest.TestCase):
    """Tests for HMAC signature generation."""
    
    def test_signature_format(self):
        sig = _generate_signature('{"test": 1}', 'secret', 1234567890)
        self.assertTrue(sig.startswith('sha256='))
    
    def test_signature_consistency(self):
        payload = '{"url":"https://test.com"}'
        secret = 'my-secret'
        timestamp = 1234567890
        
        sig1 = _generate_signature(payload, secret, timestamp)
        sig2 = _generate_signature(payload, secret, timestamp)
        
        self.assertEqual(sig1, sig2)
    
    def test_different_secrets_different_signatures(self):
        payload = '{"test": 1}'
        timestamp = 1234567890
        
        sig1 = _generate_signature(payload, 'secret1', timestamp)
        sig2 = _generate_signature(payload, 'secret2', timestamp)
        
        self.assertNotEqual(sig1, sig2)
    
    def test_different_timestamps_different_signatures(self):
        payload = '{"test": 1}'
        secret = 'secret'
        
        sig1 = _generate_signature(payload, secret, 1000)
        sig2 = _generate_signature(payload, secret, 2000)
        
        self.assertNotEqual(sig1, sig2)


class TestVerifySignature(unittest.TestCase):
    """Tests for webhook signature verification."""
    
    def test_valid_signature(self):
        payload = '{"event":"test"}'
        secret = 'test-secret'
        timestamp = str(int(time.time()))
        
        signature = _generate_signature(payload, secret, int(timestamp))
        
        valid, error = verify_signature(payload, signature, timestamp, secret)
        
        self.assertTrue(valid)
        self.assertEqual(error, '')
    
    def test_invalid_signature(self):
        payload = '{"event":"test"}'
        secret = 'test-secret'
        timestamp = str(int(time.time()))
        
        valid, error = verify_signature(payload, 'sha256=invalid', timestamp, secret)
        
        self.assertFalse(valid)
        self.assertIn('mismatch', error.lower())
    
    def test_expired_timestamp(self):
        payload = '{"event":"test"}'
        secret = 'test-secret'
        old_timestamp = str(int(time.time()) - 600)  # 10 min ago
        
        signature = _generate_signature(payload, secret, int(old_timestamp))
        
        valid, error = verify_signature(payload, signature, old_timestamp, secret)
        
        self.assertFalse(valid)
        self.assertIn('old', error.lower())
    
    def test_invalid_timestamp_format(self):
        valid, error = verify_signature('{}', 'sha256=abc', 'not-a-number', 'secret')
        
        self.assertFalse(valid)
        self.assertIn('timestamp', error.lower())
    
    def test_invalid_signature_format(self):
        timestamp = str(int(time.time()))
        
        valid, error = verify_signature('{}', 'invalid-format', timestamp, 'secret')
        
        self.assertFalse(valid)
        self.assertIn('format', error.lower())
    
    def test_custom_max_age(self):
        payload = '{"event":"test"}'
        secret = 'test-secret'
        old_timestamp = str(int(time.time()) - 120)  # 2 min ago
        
        signature = _generate_signature(payload, secret, int(old_timestamp))
        
        # Should fail with 60s max age
        valid1, _ = verify_signature(payload, signature, old_timestamp, secret, max_age_seconds=60)
        self.assertFalse(valid1)
        
        # Should pass with 300s max age
        valid2, _ = verify_signature(payload, signature, old_timestamp, secret, max_age_seconds=300)
        self.assertTrue(valid2)


class TestSendWebhook(unittest.TestCase):
    """Tests for sending webhooks."""
    
    @patch('url_reputation.webhook.urllib.request.urlopen')
    def test_send_webhook_success(self, mock_urlopen):
        mock_response = MagicMock()
        mock_response.status = 200
        mock_response.read.return_value = b'OK'
        mock_response.__enter__ = MagicMock(return_value=mock_response)
        mock_response.__exit__ = MagicMock(return_value=False)
        mock_urlopen.return_value = mock_response
        
        result = send_webhook('https://example.com/hook', {'test': 1})
        
        self.assertTrue(result['success'])
        self.assertEqual(result['status_code'], 200)
    
    @patch('url_reputation.webhook.urllib.request.urlopen')
    def test_send_webhook_with_secret(self, mock_urlopen):
        mock_response = MagicMock()
        mock_response.status = 200
        mock_response.read.return_value = b'OK'
        mock_response.__enter__ = MagicMock(return_value=mock_response)
        mock_response.__exit__ = MagicMock(return_value=False)
        mock_urlopen.return_value = mock_response
        
        result = send_webhook('https://example.com/hook', {'test': 1}, secret='my-secret')
        
        self.assertTrue(result['success'])
        
        # Verify that Request was called with signature header
        call_args = mock_urlopen.call_args
        request = call_args[0][0]
        # Header names are normalized to title case
        self.assertIn('X-signature-256', request.headers)
        self.assertTrue(request.headers['X-signature-256'].startswith('sha256='))
    
    @patch('url_reputation.webhook.urllib.request.urlopen')
    def test_send_webhook_http_error(self, mock_urlopen):
        from urllib.error import HTTPError
        mock_urlopen.side_effect = HTTPError(
            'https://example.com', 500, 'Server Error', {}, None
        )
        
        result = send_webhook('https://example.com/hook', {'test': 1})
        
        self.assertFalse(result['success'])
        self.assertEqual(result['status_code'], 500)


class TestNotifyOnRisk(unittest.TestCase):
    """Tests for conditional webhook notifications."""
    
    def test_no_notification_without_url(self):
        result = {'risk_score': 90, 'verdict': 'HIGH_RISK'}
        
        response = notify_on_risk(result)
        
        self.assertIsNone(response)
    
    @patch('url_reputation.webhook.send_webhook')
    def test_notification_on_high_risk(self, mock_send):
        mock_send.return_value = {'success': True}
        
        result = {
            'url': 'https://evil.com',
            'domain': 'evil.com',
            'risk_score': 90,
            'verdict': 'HIGH_RISK',
            'checked_at': '2026-01-20T00:00:00Z',
            'sources': {},
        }
        
        response = notify_on_risk(result, webhook_url='https://hook.example.com')
        
        self.assertIsNotNone(response)
        mock_send.assert_called_once()
    
    @patch('url_reputation.webhook.send_webhook')
    def test_no_notification_on_clean(self, mock_send):
        result = {
            'url': 'https://clean.com',
            'domain': 'clean.com',
            'risk_score': 0,
            'verdict': 'CLEAN',
            'sources': {},
        }
        
        response = notify_on_risk(result, webhook_url='https://hook.example.com')
        
        self.assertIsNone(response)
        mock_send.assert_not_called()
    
    @patch('url_reputation.webhook.send_webhook')
    def test_custom_verdicts(self, mock_send):
        mock_send.return_value = {'success': True}
        
        result = {
            'url': 'https://test.com',
            'domain': 'test.com',
            'risk_score': 30,
            'verdict': 'LOW_RISK',
            'sources': {},
        }
        
        # Should not notify with default verdicts
        response1 = notify_on_risk(result, webhook_url='https://hook.example.com')
        self.assertIsNone(response1)
        
        # Should notify with custom verdicts
        response2 = notify_on_risk(
            result,
            webhook_url='https://hook.example.com',
            verdicts=['LOW_RISK', 'MEDIUM_RISK', 'HIGH_RISK']
        )
        self.assertIsNotNone(response2)
    
    @patch('url_reputation.webhook.send_webhook')
    def test_min_risk_score(self, mock_send):
        mock_send.return_value = {'success': True}
        
        result = {
            'url': 'https://test.com',
            'domain': 'test.com',
            'risk_score': 60,
            'verdict': 'MEDIUM_RISK',
            'sources': {},
        }
        
        # Should notify (60 >= 50)
        response1 = notify_on_risk(result, webhook_url='https://hook.example.com', min_risk_score=50)
        self.assertIsNotNone(response1)
        
        # Should not notify (60 < 70)
        mock_send.reset_mock()
        response2 = notify_on_risk(
            result,
            webhook_url='https://hook.example.com',
            min_risk_score=70,
            verdicts=[]  # Disable verdict check
        )
        self.assertIsNone(response2)


if __name__ == '__main__':
    unittest.main()
