import unittest
from unittest.mock import patch, MagicMock
import os
import sys

# Add path to import app
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '../')))

from threat_feed_aggregator.utils import validate_indicator, format_timestamp
from threat_feed_aggregator.services.investigation_service import InvestigationService

class TestV19Core(unittest.TestCase):

    # --- Utility Tests ---

    def test_validate_indicator_ip(self):
        self.assertTrue(validate_indicator("1.1.1.1")[0])
        self.assertTrue(validate_indicator("8.8.8.8/32")[0])
        self.assertTrue(validate_indicator("2001:db8::/32")[0])

    def test_validate_indicator_url(self):
        self.assertTrue(validate_indicator("https://google.com")[0])
        self.assertTrue(validate_indicator("http://example.com/path")[0])

    def test_validate_indicator_domain(self):
        self.assertTrue(validate_indicator("google.com")[0])
        self.assertTrue(validate_indicator("sub.example.co.uk")[0])

    def test_validate_indicator_invalid(self):
        self.assertFalse(validate_indicator("not an ip")[0])
        self.assertFalse(validate_indicator("http:// space.com")[0])
        self.assertFalse(validate_indicator("...")[0])

    @patch('threat_feed_aggregator.config_manager.read_config')
    def test_format_timestamp_tz(self, mock_read):
        # Test UTC
        mock_read.return_value = {'timezone': 'UTC'}
        ts = "2025-12-28T12:00:00+00:00"
        self.assertEqual(format_timestamp(ts), "28/12/2025 12:00")

        # Test Istanbul (UTC+3)
        mock_read.return_value = {'timezone': 'Europe/Istanbul'}
        self.assertEqual(format_timestamp(ts), "28/12/2025 15:00")

        # Test New York (EST, UTC-5)
        mock_read.return_value = {'timezone': 'America/New_York'}
        self.assertEqual(format_timestamp(ts), "28/12/2025 07:00")

    # --- Service Layer Tests ---

    @patch('threat_feed_aggregator.services.investigation_service.whois.whois')
    @patch('threat_feed_aggregator.services.investigation_service.requests.get')
    @patch('threat_feed_aggregator.services.investigation_service.requests.post')
    def test_investigation_service_success(self, mock_post, mock_get, mock_whois):
        # Mock WHOIS
        mock_whois_entry = MagicMock()
        mock_whois_entry.text = "WHOIS RAW"
        mock_whois.return_value = mock_whois_entry

        # Mock IP-API
        mock_get_res = MagicMock()
        mock_get_res.status_code = 200
        mock_get_res.json.return_value = {'country': 'Turkey', 'isp': 'Turknet'}
        mock_get.return_value = mock_get_res

        # Mock THC
        mock_post_res = MagicMock()
        mock_post_res.status_code = 200
        mock_post_res.json.return_value = {'domains': ['example.com']}
        mock_post.return_value = mock_post_res

        result = InvestigationService.lookup_ip("1.1.1.1")
        
        self.assertTrue(result['success'])
        self.assertEqual(result['geo']['country'], 'Turkey')
        self.assertEqual(result['whois_data'], "WHOIS RAW")
        self.assertEqual(result['data']['domains'][0], 'example.com')

if __name__ == '__main__':
    unittest.main()
