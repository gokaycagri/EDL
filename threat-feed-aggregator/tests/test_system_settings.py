import unittest
from unittest.mock import patch, MagicMock
import os
import sys

# Add path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '../')))

from threat_feed_aggregator.app import app

class TestSystemSettings(unittest.TestCase):
    def setUp(self):
        app.config['TESTING'] = True
        app.config['WTF_CSRF_ENABLED'] = False
        self.client = app.test_client()
        with self.client.session_transaction() as sess:
            sess['logged_in'] = True
            sess['username'] = 'admin'

    @patch('threat_feed_aggregator.routes.system.read_config')
    @patch('threat_feed_aggregator.routes.system.write_config')
    def test_update_base_url(self, mock_write, mock_read):
        """Test updating the System Base URL setting."""
        mock_read.return_value = {"source_urls": [], "timezone": "UTC"}
        
        # Test updating with a new base URL
        response = self.client.post('/system/update_settings', data={
            'base_url': 'https://10.9.102.12',
            'timezone': 'Europe/Istanbul',
            'indicator_lifetime_days': '30'
        })
        
        self.assertEqual(response.status_code, 302)
        mock_write.assert_called_once()
        
        # Verify the base_url was formatted correctly (trailing slash added)
        config_saved = mock_write.call_args[0][0]
        self.assertEqual(config_saved['base_url'], 'https://10.9.102.12/')
        self.assertEqual(config_saved['timezone'], 'Europe/Istanbul')

    @patch('threat_feed_aggregator.services.feed_health.get_all_health_statuses', return_value={})
    @patch('threat_feed_aggregator.routes.system.is_mfa_enabled', return_value=False)
    @patch('threat_feed_aggregator.routes.system.get_ldap_group_mappings', return_value=[])
    @patch('threat_feed_aggregator.routes.system.get_admin_profiles', return_value=[])
    @patch('threat_feed_aggregator.routes.system.get_all_users', return_value=[])
    @patch('threat_feed_aggregator.routes.system.read_config')
    def test_integrations_page_renders_with_base_url(self, mock_read, mock_users, mock_profiles, mock_ldap, mock_mfa, mock_health):
        """Test that the integrations tab correctly displays the configured base URL."""
        mock_read.return_value = {
            "source_urls": [],
            "base_url": "https://my-threat-feed.local/",
            "api_clients": [{"name": "Test", "api_key": "secret123"}]
        }

        response = self.client.get('/system/')
        self.assertEqual(response.status_code, 200)

        # Check if the configured URL is present in the rendered HTML
        html = response.data.decode('utf-8')
        self.assertIn('https://my-threat-feed.local/api/deceptor/block', html)

    @patch('threat_feed_aggregator.routes.system.read_config')
    @patch('threat_feed_aggregator.routes.system.write_config')
    def test_add_api_client(self, mock_write, mock_read):
        """Test adding a new API client (API Key) through the system route."""
        mock_read.return_value = {"api_clients": []}
        
        response = self.client.post('/system/api_client/add', data={
            'name': 'FortiDeceptor Test Client',
            'allowed_ips': '10.0.0.1, 10.0.0.2'
        })
        
        self.assertEqual(response.status_code, 302)
        mock_write.assert_called_once()
        
        # Verify saved data
        config_saved = mock_write.call_args[0][0]
        self.assertEqual(len(config_saved['api_clients']), 1)
        client = config_saved['api_clients'][0]
        self.assertEqual(client['name'], 'FortiDeceptor Test Client')
        self.assertEqual(client['allowed_ips'], ['10.0.0.1', '10.0.0.2'])
        self.assertTrue(len(client['api_key']) >= 32)

if __name__ == '__main__':
    unittest.main()
