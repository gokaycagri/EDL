import unittest
from unittest.mock import patch, MagicMock
import os
import sys
import json

# Add path to import app
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '../')))

from threat_feed_aggregator.app import app

class TestMissingCoverage(unittest.TestCase):
    def setUp(self):
        app.config['TESTING'] = True
        app.config['WTF_CSRF_ENABLED'] = False 
        self.client = app.test_client()

    def login(self):
        """Helper to simulate a logged-in user session."""
        with self.client.session_transaction() as sess:
            sess['logged_in'] = True
            sess['username'] = 'admin'
            sess['role'] = 'admin' # Assuming role might be needed

    # --- Tools Routes Tests ---

    def test_investigate_page_load(self):
        """Test that the investigation tool page loads."""
        self.login()
        response = self.client.get('/tools/investigate')
        self.assertEqual(response.status_code, 200)
        self.assertIn(b'Threat Investigation', response.data)

    @patch('threat_feed_aggregator.services.investigation_service.whois.whois')
    @patch('threat_feed_aggregator.services.investigation_service.requests.get')
    @patch('threat_feed_aggregator.services.investigation_service.requests.post')
    def test_lookup_ip_success(self, mock_post, mock_get, mock_whois):
        """Test the IP lookup API with successful external responses."""
        self.login()
        
        # Mock WHOIS
        mock_whois_entry = MagicMock()
        mock_whois_entry.text = "Mock WHOIS Data"
        mock_whois.return_value = mock_whois_entry

        # Mock External API (ip-api.com)
        mock_get_res = MagicMock()
        mock_get_res.status_code = 200
        mock_get_res.json.return_value = {'country': 'TestCountry', 'isp': 'TestISP'}
        mock_get.return_value = mock_get_res

        # Mock External API (ip.thc.org)
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {"domains": ["example.com"], "count": 1}
        mock_post.return_value = mock_response

        payload = {'ip': '8.8.8.8'}
        response = self.client.post('/tools/api/lookup_ip', json=payload)
        
        self.assertEqual(response.status_code, 200)
        data = response.json
        self.assertTrue(data['success'])
        self.assertEqual(data['whois_data'], "Mock WHOIS Data")
        self.assertEqual(data['data']['domains'][0], "example.com")

    @patch('threat_feed_aggregator.services.investigation_service.whois.whois')
    @patch('threat_feed_aggregator.services.investigation_service.requests.get')
    @patch('threat_feed_aggregator.services.investigation_service.requests.post')
    def test_lookup_ip_failure_external(self, mock_post, mock_get, mock_whois):
        """Test the IP lookup API when external API fails."""
        self.login()
        
        # Mock WHOIS (still works)
        mock_whois_entry = MagicMock()
        mock_whois_entry.text = "Mock WHOIS Data"
        mock_whois.return_value = mock_whois_entry

        # Mock External API Failure
        mock_get.return_value = MagicMock(status_code=500)
        mock_post.return_value = MagicMock(status_code=500)

        payload = {'ip': '8.8.8.8'}
        response = self.client.post('/tools/api/lookup_ip', json=payload)
        
        # New logic returns 200 even if external API fails (graceful degradation)
        self.assertEqual(response.status_code, 200)
        self.assertTrue(response.json['success'])
        # The 'data' field might be empty, but request succeeds
        self.assertEqual(response.json['data'], {})

    def test_lookup_ip_no_input(self):
        """Test IP lookup with missing input."""
        self.login()
        response = self.client.post('/tools/api/lookup_ip', json={})
        self.assertEqual(response.status_code, 400)

    # --- System Routes Tests ---

    @patch('threat_feed_aggregator.routes.system.write_config')
    @patch('threat_feed_aggregator.routes.system.read_config')
    def test_update_proxy(self, mock_read, mock_write):
        """Test updating proxy settings."""
        self.login()
        mock_read.return_value = {'source_urls': []}

        data = {
            'proxy_enabled': 'on',
            'proxy_server': 'http://10.10.10.10',
            'proxy_port': '8080',
            'proxy_username': 'user',
            'proxy_password': 'pass'
        }
        
        response = self.client.post('/system/update_proxy', data=data, follow_redirects=True)
        self.assertEqual(response.status_code, 200)
        
        mock_write.assert_called_once()
        written = mock_write.call_args[0][0]
        self.assertTrue(written['proxy']['enabled'])
        self.assertEqual(written['proxy']['server'], '10.10.10.10') # Protocol stripped

    @patch('threat_feed_aggregator.routes.system.write_config')
    @patch('threat_feed_aggregator.routes.system.read_config')
    def test_add_api_client(self, mock_read, mock_write):
        """Test adding a new API client."""
        self.login()
        mock_read.return_value = {'api_clients': [], 'source_urls': []}
        
        data = {
            'name': 'TestClient',
            'allowed_ips': '1.1.1.1, 2.2.2.2'
        }
        
        response = self.client.post('/system/api_client/add', data=data, follow_redirects=True)
        self.assertEqual(response.status_code, 200)
        
        mock_write.assert_called_once()
        written = mock_write.call_args[0][0]
        self.assertEqual(len(written['api_clients']), 1)
        self.assertEqual(written['api_clients'][0]['name'], 'TestClient')
        self.assertEqual(written['api_clients'][0]['allowed_ips'], ['1.1.1.1', '2.2.2.2'])

    @patch('threat_feed_aggregator.routes.system.write_config')
    @patch('threat_feed_aggregator.routes.system.read_config')
    def test_remove_api_client(self, mock_read, mock_write):
        """Test removing an API client."""
        self.login()
        mock_read.return_value = {'api_clients': [{'id': '123', 'name': 'Test'}], 'source_urls': []}
        
        response = self.client.post('/system/api_client/remove', data={'client_id': '123'}, follow_redirects=True)
        self.assertEqual(response.status_code, 200)
        
        mock_write.assert_called_once()
        written = mock_write.call_args[0][0]
        self.assertEqual(len(written['api_clients']), 0)

    @patch('threat_feed_aggregator.routes.system.add_whitelist_item')
    @patch('threat_feed_aggregator.routes.system.delete_whitelisted_indicators')
    def test_add_whitelist_item(self, mock_delete, mock_add):
        """Test adding a whitelist item."""
        self.login()
        mock_add.return_value = (True, "Success")
        
        response = self.client.post('/system/whitelist/add', data={'item': '1.1.1.1'}, follow_redirects=True)
        self.assertEqual(response.status_code, 200)
        
        mock_add.assert_called_once()
        mock_delete.assert_called_once_with(['1.1.1.1'])

    @patch('threat_feed_aggregator.routes.system.remove_whitelist_item')
    def test_remove_whitelist_item(self, mock_remove):
        """Test removing a whitelist item."""
        self.login()
        response = self.client.get('/system/whitelist/remove/1', follow_redirects=True)
        self.assertEqual(response.status_code, 200)
        mock_remove.assert_called_once_with(1)

    # --- Dashboard/Data Routes Tests ---

    @patch('flask.send_from_directory')
    def test_download_file(self, mock_send):
        """Test file download endpoint."""
        self.login()
        # Mock send_from_directory to return a simple response or object
        mock_send.return_value = "File Content" 
        
        response = self.client.get('/data/test_file.txt')
        
        # In a real app send_from_directory returns a Response object, 
        # here we just check if it was called correctly.
        mock_send.assert_called_once()

    # --- New API Endpoints (v1.9) ---

    @patch('threat_feed_aggregator.routes.api.read_config')
    @patch('threat_feed_aggregator.routes.api.threading.Thread')
    def test_run_single_feed(self, mock_thread, mock_read):
        self.login()
        mock_read.return_value = {'source_urls': [{'name': 'TestFeed', 'url': 'http://test.com'}]}
        
        response = self.client.get('/api/run_single/TestFeed')
        self.assertEqual(response.status_code, 200)
        self.assertIn('running', response.json['status'])
        mock_thread.assert_called_once()

    @patch('threat_feed_aggregator.app.scheduler.get_jobs')
    @patch('threat_feed_aggregator.config_manager.read_config')
    def test_get_scheduled_jobs(self, mock_read, mock_jobs):
        self.login()
        mock_read.return_value = {'timezone': 'UTC'}
        
        # Mock a job
        mock_job = MagicMock()
        mock_job.name = "Test Job"
        import datetime
        import pytz
        mock_job.next_run_time = datetime.datetime(2025, 12, 28, 12, 0, tzinfo=pytz.UTC)
        mock_jobs.return_value = [mock_job]
        
        response = self.client.get('/api/scheduled_jobs')
        self.assertEqual(response.status_code, 200)
        self.assertEqual(len(response.json), 1)
        self.assertEqual(response.json[0]['name'], "Test Job")

    @patch('threat_feed_aggregator.routes.api.clear_logs')
    def test_clear_live_logs(self, mock_clear):
        self.login()
        response = self.client.post('/api/live_logs/clear')
        self.assertEqual(response.status_code, 200)
        mock_clear.assert_called_once()
