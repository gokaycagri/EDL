import unittest
from unittest.mock import patch, MagicMock
import os
import sys

# Add path to import app
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '../')))

from threat_feed_aggregator.app import app

class TestGuiViews(unittest.TestCase):
    def setUp(self):
        app.config['TESTING'] = True
        app.config['WTF_CSRF_ENABLED'] = False # Disable CSRF for easier form testing
        self.client = app.test_client()

    def login(self):
        """Helper to simulate a logged-in user session."""
        with self.client.session_transaction() as sess:
            sess['logged_in'] = True
            sess['username'] = 'admin'

    def test_login_page_load(self):
        """Test that the login page loads correctly."""
        response = self.client.get('/login')
        self.assertEqual(response.status_code, 200)
        self.assertIn(b'Login', response.data)

    @patch('threat_feed_aggregator.routes.auth.check_credentials')
    def test_login_action_success(self, mock_check):
        """Test successful login redirection."""
        mock_check.return_value = (True, "Login successful", {"username": "admin", "permissions": {}})
        response = self.client.post('/login', data={'username': 'admin', 'password': 'password'}, follow_redirects=True)
        # Should redirect to index, so we check for text present on dashboard
        self.assertIn(b'Dashboard', response.data)
        self.assertIn(b'Sign Out', response.data)

    @patch('threat_feed_aggregator.routes.auth.check_credentials')
    def test_login_action_failure(self, mock_check):
        """Test failed login stays on login page with error."""
        mock_check.return_value = (False, "Invalid credentials", None)
        response = self.client.post('/login', data={'username': 'admin', 'password': 'wrong'}, follow_redirects=True)
        self.assertIn(b'Invalid credentials', response.data)
        self.assertIn(b'Login', response.data) # Still on login page

    @patch('threat_feed_aggregator.routes.dashboard.get_unique_indicator_count')
    @patch('threat_feed_aggregator.routes.dashboard.get_indicator_counts_by_type')
    @patch('threat_feed_aggregator.routes.dashboard.read_stats')
    @patch('threat_feed_aggregator.routes.dashboard.read_config')
    def test_dashboard_load(self, mock_config, mock_stats, mock_counts, mock_total):
        """Test that dashboard loads with stats."""
        self.login()
        
        # Setup mocks for dashboard data
        mock_config.return_value = {'source_urls': [{'name': 'TestFeed', 'url': 'http://test.com'}]}
        mock_stats.return_value = {'TestFeed': {'count': 100}}
        mock_counts.return_value = {'ip': 50, 'domain': 10}
        mock_total.return_value = 60

        response = self.client.get('/')
        self.assertEqual(response.status_code, 200)
        
        # Check if key elements are rendered
        self.assertIn(b'Dashboard', response.data)
        self.assertIn(b'TestFeed', response.data) # Source name
        self.assertIn(b'Total Indicators', response.data)

    @patch('threat_feed_aggregator.routes.system.write_config')
    @patch('threat_feed_aggregator.routes.system.read_config')
    @patch('threat_feed_aggregator.app.update_scheduled_jobs')
    def test_add_source(self, mock_update_jobs, mock_read, mock_write):
        """Test adding a new threat feed source."""
        self.login()
        
        # Mock initial config
        mock_read.return_value = {"source_urls": []}
        
        data = {
            'name': 'NewSource',
            'url': 'http://example.com/feed.txt',
            'format': 'text',
            'confidence': 85,
            'schedule_interval_minutes': 60
        }
        
        response = self.client.post('/system/add_source', data=data, follow_redirects=True)
        self.assertEqual(response.status_code, 200)
        
        # Verify write_config was called with new data
        mock_write.assert_called_once()
        args = mock_write.call_args[0][0]
        self.assertEqual(len(args['source_urls']), 1)
        self.assertEqual(args['source_urls'][0]['name'], 'NewSource')
        self.assertEqual(args['source_urls'][0]['confidence'], 85)

    @patch('threat_feed_aggregator.routes.system.write_config')
    @patch('threat_feed_aggregator.routes.system.read_config')
    def test_update_settings(self, mock_read, mock_write):
        """Test updating global settings (retention)."""
        self.login()
        
        mock_read.return_value = {"indicator_lifetime_days": 30, "source_urls": []}
        
        response = self.client.post('/system/update_settings', data={'indicator_lifetime_days': 60}, follow_redirects=True)
        self.assertEqual(response.status_code, 200)
        
        # Verify update
        mock_write.assert_called_once()
        written_config = mock_write.call_args[0][0]
        self.assertEqual(written_config['indicator_lifetime_days'], 60) # app.py converts to int

if __name__ == '__main__':
    unittest.main()