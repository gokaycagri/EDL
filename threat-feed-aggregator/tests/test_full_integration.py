import os
import sys
import tempfile
import unittest
from unittest.mock import MagicMock

# Mock missing dependencies only if not installed
for _mod in [
    'werkzeug', 'werkzeug.security', 'flask', 'flask_login',
    'aiohttp', 'apscheduler', 'apscheduler.schedulers.background',
    'apscheduler.jobstores.sqlalchemy', 'geoip2', 'geoip2.database',
]:
    if _mod not in sys.modules:
        try:
            __import__(_mod)
        except ImportError:
            sys.modules[_mod] = MagicMock()

# Add project root to path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

# Mock DATA_DIR
import threat_feed_aggregator.config_manager

threat_feed_aggregator.config_manager.DATA_DIR = "."

from threat_feed_aggregator.database.schema import init_db
from threat_feed_aggregator.repositories.custom_list_repo import create_custom_list, get_custom_list_by_token
from threat_feed_aggregator.repositories.indicator_repo import (
    get_indicators_paginated,
    upsert_indicators_bulk,
)
from threat_feed_aggregator.repositories.whitelist_repo import add_whitelist_item


class TestFullIntegration(unittest.TestCase):
    def setUp(self):
        self._db_fd, self._db_path = tempfile.mkstemp(suffix='.db')
        os.environ['TEST_DB_NAME'] = self._db_path
        os.environ['DB_TYPE'] = 'sqlite'

        import threat_feed_aggregator.database.connection as _conn_mod
        _conn_mod.DB_NAME = self._db_path

        init_db()

    def tearDown(self):
        os.close(self._db_fd)
        os.remove(self._db_path)
        os.environ.pop('TEST_DB_NAME', None)

    def test_end_to_end_flow(self):
        print("\n--- Starting End-to-End Integration Test ---")

        # 1. Ingest Data (Simulate Fetch)
        print("1. Ingesting Data...")
        indicators = [
            ("1.1.1.1", "US", "ip"),
            ("2.2.2.2", "DE", "ip"),
            ("bad.com", "CN", "domain"),
            ("phishing.site", "TR", "domain"),
            ("8.8.8.8", "US", "ip") # Will be whitelisted
        ]
        # Simulate Feodo
        upsert_indicators_bulk([indicators[0], indicators[1]], source_name="Feodo Tracker")
        # Simulate URLHaus
        upsert_indicators_bulk([indicators[2]], source_name="URLHaus")
        # Simulate USOM
        upsert_indicators_bulk([indicators[3]], source_name="USOM")
        # Simulate AlienVault (whitelisted item)
        upsert_indicators_bulk([indicators[4]], source_name="AlienVault")

        # 2. Whitelist Cleanup
        print("2. Testing Whitelist Cleanup...")
        add_whitelist_item("8.8.8.8", "Google DNS")

        # 3. Verify Risk Analysis (Pagination & Filtering)
        print("3. Testing Risk Analysis...")
        total, filtered, items = get_indicators_paginated(filters={'source': 'Feodo'})
        self.assertEqual(len(items), 2)
        print(f"   -> Found {len(items)} items for Source 'Feodo' (Expected 2)")

        # 4. Custom EDL
        print("4. Testing Custom EDL...")
        list_id, token = create_custom_list("My List", ["Feodo Tracker"], ["ip"], "text")
        fetched_list = get_custom_list_by_token(token)
        self.assertEqual(fetched_list['name'], "My List")
        print("   -> Custom List created and retrieved.")

        # 5. Internal Search
        print("5. Testing Internal Search...")
        from threat_feed_aggregator.database.connection import get_db_connection
        conn = get_db_connection()
        cursor = conn.execute("SELECT source_name FROM indicator_sources WHERE indicator = '1.1.1.1'")
        rows = cursor.fetchall()
        conn.close()
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]['source_name'], 'Feodo Tracker')
        print("   -> Internal search found '1.1.1.1' in 'Feodo Tracker'.")

        print("--- End-to-End Test Passed ---")

if __name__ == '__main__':
    unittest.main()
