import unittest
from unittest.mock import patch, MagicMock
import os
import sys
import json

# Add path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '../')))

from threat_feed_aggregator.app import app

class TestFortiDeceptor(unittest.TestCase):
    def setUp(self):
        app.config['TESTING'] = True
        app.config['WTF_CSRF_ENABLED'] = False
        self.client = app.test_client()
        self.api_key = "4Sb4rLIIlEONmHo768OaLIGcTrmK9Mp6"

        # Mock the config to allow our test API key
        self.mock_config = {
            "api_clients": [
                {"name": "Test Client", "api_key": self.api_key, "allowed_ips": []}
            ]
        }

    @patch('threat_feed_aggregator.routes.auth.read_config')
    @patch('threat_feed_aggregator.routes.api.add_api_blacklist_item')
    @patch('threat_feed_aggregator.routes.api.regenerate_edl_files')
    def test_deceptor_block_via_header(self, mock_regen, mock_add, mock_read_config):
        """Test blocking an IP using the whblockheader HTTP Header."""
        mock_read_config.return_value = self.mock_config
        mock_add.return_value = (True, "Item added to blacklist.")
        
        headers = {
            'Authorization': f'Bearer {self.api_key}',
            'whblockheader': '192.168.1.50'
        }
        
        response = self.client.post('/api/deceptor/block', headers=headers)
        
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json['status'], 'success')
        mock_add.assert_called_once()
        # Verify the IP was passed correctly
        self.assertEqual(mock_add.call_args[0][0], '192.168.1.50')

    @patch('threat_feed_aggregator.routes.auth.read_config')
    @patch('threat_feed_aggregator.routes.api.add_api_blacklist_item')
    @patch('threat_feed_aggregator.routes.api.regenerate_edl_files')
    def test_deceptor_block_via_json(self, mock_regen, mock_add, mock_read_config):
        """Test blocking an IP using the whblockdata in JSON body."""
        mock_read_config.return_value = self.mock_config
        mock_add.return_value = (True, "Item added to blacklist.")
        
        headers = {'Authorization': f'Bearer {self.api_key}'}
        data = {'whblockdata': '10.0.0.5', 'expiry': '7200'}
        
        response = self.client.post('/api/deceptor/block', 
                                    headers=headers, 
                                    data=json.dumps(data),
                                    content_type='application/json')
        
        self.assertEqual(response.status_code, 200)
        self.assertTrue(mock_add.called)
        # Check if IP and expiry was correctly handled
        args, kwargs = mock_add.call_args
        self.assertEqual(args[0], '10.0.0.5')
        self.assertIn('Expiry: 7200s', kwargs['comment'])

    @patch('threat_feed_aggregator.routes.auth.read_config')
    @patch('threat_feed_aggregator.routes.api.remove_api_blacklist_item')
    @patch('threat_feed_aggregator.routes.api.regenerate_edl_files')
    def test_deceptor_unblock(self, mock_regen, mock_remove, mock_read_config):
        """Test unblocking an IP via deceptor API."""
        mock_read_config.return_value = self.mock_config
        mock_remove.return_value = True
        
        headers = {
            'Authorization': self.api_key, # Test without Bearer prefix
            'whunblockheader': '192.168.1.50'
        }
        
        response = self.client.post('/api/deceptor/unblock', headers=headers)
        
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json['status'], 'success')
        mock_remove.assert_called_with('192.168.1.50')

    @patch('threat_feed_aggregator.routes.auth.read_config')
    def test_unauthorized_access(self, mock_read_config):
        """Test that requests without a valid API key are rejected."""
        mock_read_config.return_value = self.mock_config
        
        response = self.client.post('/api/deceptor/block', headers={'whblockheader': '1.1.1.1'})
        self.assertEqual(response.status_code, 401)
        self.assertIn('Unauthorized', response.json['message'])

if __name__ == '__main__':
    unittest.main()
