import unittest
import os
import sys
import tempfile
import json

# Add module to path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '../')))

from threat_feed_aggregator.app import app, init_db
from threat_feed_aggregator.db_manager import get_db_connection

class TestAppIntegration(unittest.TestCase):
    def setUp(self):
        self.db_fd, self.db_path = tempfile.mkstemp()
        app.config['TESTING'] = True
        app.config['WTF_CSRF_ENABLED'] = False # Disable CSRF for testing
        
        # We can't easily mock the DB path in the imported module without patching, 
        # but for now we'll just test the existing setup. 
        # Since the app initializes DB on import, it's already using the real DB file.
        # This is a bit risky for "unit" tests but acceptable for "integration/sanity" check on a dev machine.
        # Ideally, we would patch DATA_DIR in config_manager.
        
        self.client = app.test_client()

    def tearDown(self):
        os.close(self.db_fd)
        os.remove(self.db_path)

    def test_login_page_loads(self):
        response = self.client.get('/login')
        self.assertEqual(response.status_code, 200)
        self.assertIn(b'Login', response.data)

    def test_index_redirects_when_not_logged_in(self):
        response = self.client.get('/')
        self.assertEqual(response.status_code, 302)
        # Location header is string in newer Werkzeug
        self.assertIn('/login', response.headers['Location'])

    def test_protected_endpoint_requires_auth(self):
        # /api/history is a valid route checking login
        response = self.client.get('/api/history')
        self.assertEqual(response.status_code, 302)
        self.assertIn('/login', response.headers['Location'])

if __name__ == '__main__':
    unittest.main()
