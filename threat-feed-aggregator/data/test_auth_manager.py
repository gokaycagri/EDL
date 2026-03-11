import unittest
from unittest.mock import patch, MagicMock
import os
import json
from threat_feed_aggregator.auth_manager import check_credentials
from threat_feed_aggregator.config_manager import read_config

# Ensure a dummy config file exists for testing read_config
DUMMY_CONFIG_DIR = os.path.join(os.path.dirname(__file__), "temp_auth_config")
DUMMY_CONFIG_PATH = os.path.join(DUMMY_CONFIG_DIR, "config.json")

class TestAuthManager(unittest.TestCase):

    @patch('threat_feed_aggregator.auth_manager.local_user_exists')
    @patch('threat_feed_aggregator.auth_manager.verify_local_user')
    @patch('threat_feed_aggregator.auth_manager.get_user_permissions')
    def test_local_admin_login_success(self, mock_perms, mock_verify, mock_exists):
        mock_exists.return_value = True
        mock_verify.return_value = True
        mock_perms.return_value = {}
        success, message, _ = check_credentials('admin', 'correct_password')
        self.assertTrue(success)
        self.assertEqual(message, "Local login successful.")
        mock_verify.assert_called_once_with('admin', 'correct_password')

    @patch('threat_feed_aggregator.auth_manager.local_user_exists')
    @patch('threat_feed_aggregator.auth_manager.verify_local_user')
    def test_local_admin_login_failure(self, mock_verify, mock_exists):
        mock_exists.return_value = True
        mock_verify.return_value = False
        # We need to ensure LDAP fallback fails too, so we can mock read_config to disable it
        with patch('threat_feed_aggregator.config_manager.read_config', return_value={'auth': {'ldap_enabled': False}}):
            success, message, _ = check_credentials('admin', 'wrong_password')
            self.assertFalse(success)
            self.assertEqual(message, "Invalid credentials.")

    @patch('threat_feed_aggregator.config_manager.read_config')
    @patch('threat_feed_aggregator.auth_manager.local_user_exists')
    @patch('threat_feed_aggregator.auth_manager.verify_local_user')
    def test_local_admin_login_failure_ldap_disabled(self, mock_verify, mock_exists, mock_read_config):
        mock_exists.return_value = True
        mock_verify.return_value = False
        mock_read_config.return_value = {'auth': {'ldap_enabled': False}}
        
        success, message, _ = check_credentials('admin', 'wrong_password')
        self.assertFalse(success)
        self.assertEqual(message, "Invalid credentials.")

    @patch('threat_feed_aggregator.config_manager.read_config')
    @patch('threat_feed_aggregator.auth_manager.local_user_exists')
    def test_ldap_disabled(self, mock_exists, mock_read_config):
        mock_exists.return_value = False
        mock_read_config.return_value = {'auth': {'ldap_enabled': False}}
        # Since 'admin' is checked first, need to ensure it fails to reach LDAP check
        success, message, _ = check_credentials('non_admin_user', 'password')
        self.assertFalse(success)
        self.assertEqual(message, "LDAP authentication is disabled.")

    @patch('threat_feed_aggregator.config_manager.read_config')
    @patch('threat_feed_aggregator.auth_manager.local_user_exists')
    def test_ldap_enabled_not_configured(self, mock_exists, mock_read_config):
        mock_exists.return_value = False
        mock_read_config.return_value = {'auth': {'ldap_enabled': True, 'ldap_servers': []}} 
        success, message, _ = check_credentials('user', 'password')
        self.assertFalse(success)
        self.assertEqual(message, "LDAP server list is empty.")

    @patch('threat_feed_aggregator.config_manager.read_config')
    @patch('threat_feed_aggregator.auth_manager.Connection')
    @patch('threat_feed_aggregator.auth_manager.Server')
    @patch('threat_feed_aggregator.auth_manager.get_profile_by_ldap_groups')
    @patch('threat_feed_aggregator.auth_manager.local_user_exists')
    def test_ldap_login_success(self, mock_exists, mock_get_profile, mock_server, mock_connection, mock_read_config):
        mock_exists.return_value = False
        mock_read_config.return_value = {
            'auth': {'ldap_enabled': True, 'ldap_servers': [{'server': 'ldap.example.com', 'port': 389, 'domain': 'dc=example,dc=com'}]}
        }
        mock_conn_instance = MagicMock()
        mock_conn_instance.bound = True
        mock_conn_instance.entries = [MagicMock()] # Mock user entry
        mock_connection.return_value = mock_conn_instance
        
        mock_get_profile.return_value = 1 # Admin Profile

        success, message, _ = check_credentials('testuser', 'ldappassword')
        self.assertTrue(success)
        self.assertEqual(message, "LDAP Login Successful.")
        mock_server.assert_called_with('ldap.example.com', port=389, get_info=unittest.mock.ANY, use_ssl=False, tls=None, connect_timeout=5)
        mock_conn_instance.unbind.assert_called_once()

    @patch('threat_feed_aggregator.config_manager.read_config')
    @patch('threat_feed_aggregator.auth_manager.Connection')
    @patch('threat_feed_aggregator.auth_manager.Server')
    @patch('threat_feed_aggregator.auth_manager.local_user_exists')
    def test_ldap_login_failure(self, mock_exists, mock_server, mock_connection, mock_read_config):
        mock_exists.return_value = False
        mock_read_config.return_value = {
             'auth': {'ldap_enabled': True, 'ldap_servers': [{'server': 'ldap.example.com', 'port': 389, 'domain': 'dc=example,dc=com'}]}
        }
        mock_conn_instance = MagicMock()
        mock_conn_instance.bound = False # Bind failed
        mock_connection.return_value = mock_conn_instance

        success, message, _ = check_credentials('testuser', 'wrongpassword')
        self.assertFalse(success)
        self.assertIn("LDAP Auth Failed", message)

    @patch('threat_feed_aggregator.config_manager.read_config')
    @patch('threat_feed_aggregator.auth_manager.Connection', side_effect=Exception("LDAP connection error"))
    @patch('threat_feed_aggregator.auth_manager.Server')
    @patch('threat_feed_aggregator.auth_manager.local_user_exists')
    def test_ldap_login_exception(self, mock_exists, mock_server, mock_connection, mock_read_config):
        mock_exists.return_value = False
        mock_read_config.return_value = {
             'auth': {'ldap_enabled': True, 'ldap_servers': [{'server': 'ldap.example.com', 'port': 389, 'domain': 'dc=example,dc=com'}]}
        }
        success, message, _ = check_credentials('testuser', 'password')
        self.assertFalse(success)
        self.assertIn("LDAP Auth Failed", message)

# New test class for read_config to better isolate patching CONFIG_FILE
class TestReadConfig(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        os.makedirs(DUMMY_CONFIG_DIR, exist_ok=True)

    @classmethod
    def tearDownClass(cls):
        if os.path.exists(DUMMY_CONFIG_PATH):
            os.remove(DUMMY_CONFIG_PATH)
        if os.path.exists(DUMMY_CONFIG_DIR):
            os.rmdir(DUMMY_CONFIG_DIR)

    def setUp(self):
        # Ensure dummy config is empty or reset before each test
        with open(DUMMY_CONFIG_PATH, "w") as f:
            f.write("{}")

    @patch('threat_feed_aggregator.config_manager.CONFIG_FILE', DUMMY_CONFIG_PATH)
    def test_read_config_file_not_found(self):
        os.remove(DUMMY_CONFIG_PATH) # Ensure file does not exist
        config = read_config()
        self.assertEqual(config, {"source_urls": []})

    @patch('threat_feed_aggregator.config_manager.CONFIG_FILE', DUMMY_CONFIG_PATH)
    def test_read_config_json_decode_error(self):
        # Write invalid JSON to dummy config file
        with open(DUMMY_CONFIG_PATH, "w") as f:
            f.write("invalid json")
        
        # Should return fallback empty config
        with patch('threat_feed_aggregator.config_manager.logger'):
             config = read_config()
             self.assertEqual(config, {"source_urls": []})

    @patch('threat_feed_aggregator.config_manager.CONFIG_FILE', DUMMY_CONFIG_PATH)
    def test_read_config_success(self):
        test_config_content = {"auth": {"ldap": {"enabled": True}}}
        with open(DUMMY_CONFIG_PATH, "w") as f:
            json.dump(test_config_content, f)
        
        config = read_config()
        self.assertEqual(config, test_config_content)
