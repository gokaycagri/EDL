import unittest
from unittest.mock import patch, MagicMock
import os
import sys

# Add path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '../')))

from threat_feed_aggregator.app import app

class TestWebEndpoints(unittest.TestCase):
    def setUp(self):
        app.config['TESTING'] = True
        app.config['WTF_CSRF_ENABLED'] = False
        self.client = app.test_client()
        
        # Bypass login for testing protected endpoints requires handling session
        with self.client.session_transaction() as sess:
            sess['logged_in'] = True
            sess['username'] = 'admin'

    @patch('threat_feed_aggregator.routes.api.process_microsoft_feeds')
    def test_ms365_endpoint(self, mock_process):
        # Mock success
        mock_process.return_value = (True, "Success")
        response = self.client.post('/api/update_ms365')
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json['status'], 'success')

        # Mock failure
        mock_process.return_value = (False, "Failure")
        response = self.client.post('/api/update_ms365')
        self.assertEqual(response.status_code, 200) # Returns 200 with error status JSON
        self.assertEqual(response.json['status'], 'error')

    @patch('threat_feed_aggregator.routes.api.process_github_feeds')
    def test_github_endpoint(self, mock_process):
        mock_process.return_value = (True, "GitHub Updated")
        response = self.client.post('/api/update_github')
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json['message'], 'GitHub Updated')

    @patch('threat_feed_aggregator.routes.api.process_azure_feeds')
    def test_azure_endpoint(self, mock_process):
        mock_process.return_value = (True, "Azure Updated")
        response = self.client.post('/api/update_azure')
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json['status'], 'success')

if __name__ == '__main__':
    unittest.main()