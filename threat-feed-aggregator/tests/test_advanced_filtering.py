import os
import sys
import tempfile
import unittest

# Add project root to path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

# Mock DATA_DIR
import threat_feed_aggregator.config_manager
threat_feed_aggregator.config_manager.DATA_DIR = "."

from threat_feed_aggregator.database.schema import init_db
from threat_feed_aggregator.repositories.indicator_repo import upsert_indicators_bulk, get_indicators_paginated

class TestAdvancedFiltering(unittest.TestCase):
    def setUp(self):
        # Use a temp file DB so all functions (including db_readonly) use the same DB
        self._db_fd, self._db_path = tempfile.mkstemp(suffix='.db')
        os.environ['TEST_DB_NAME'] = self._db_path
        os.environ['DB_TYPE'] = 'sqlite'

        # Re-set DB_NAME in the connection module to pick up the new path
        import threat_feed_aggregator.database.connection as _conn_mod
        _conn_mod.DB_NAME = self._db_path

        # Initialize schema via the standard path (no conn arg)
        init_db()

        # Seed Data
        from threat_feed_aggregator.database.connection import get_db_connection
        conn = get_db_connection()
        # 1. Feodo (Botnet) -> IP: 1.1.1.1 (Score 95 - Critical), 2.2.2.2 (Score 50 - Medium)
        # 2. URLHaus (Malware) -> Domain: bad.com (Score 80 - High)
        upsert_indicators_bulk([("1.1.1.1", "US", "ip"), ("2.2.2.2", "DE", "ip")], source_name="Feodo Tracker")
        upsert_indicators_bulk([("bad.com", "CN", "domain")], source_name="URLHaus")

        # Manually update scores for testing levels
        conn.execute("UPDATE indicators SET risk_score = 95 WHERE indicator = '1.1.1.1'")
        conn.execute("UPDATE indicators SET risk_score = 50 WHERE indicator = '2.2.2.2'")
        conn.execute("UPDATE indicators SET risk_score = 80 WHERE indicator = 'bad.com'")
        conn.commit()
        conn.close()

    def tearDown(self):
        os.close(self._db_fd)
        os.remove(self._db_path)
        os.environ.pop('TEST_DB_NAME', None)

    def test_filter_by_source(self):
        # Filter for 'Feodo'
        total, filtered, items = get_indicators_paginated(filters={'source': 'Feodo'})
        self.assertEqual(len(items), 2)
        indicators = sorted([i['indicator'] for i in items])
        self.assertEqual(indicators, ['1.1.1.1', '2.2.2.2'])

    def test_filter_by_tag_botnet(self):
        # Filter for 'Botnet' (Should match Feodo)
        total, filtered, items = get_indicators_paginated(filters={'tag': 'Botnet'})
        self.assertEqual(len(items), 2)
        self.assertEqual(items[0]['indicator'], '1.1.1.1')

    def test_filter_by_level_critical(self):
        # Filter for 'Critical' (Score >= 90)
        total, filtered, items = get_indicators_paginated(filters={'level': 'Critical'})
        self.assertEqual(len(items), 1)
        self.assertEqual(items[0]['indicator'], '1.1.1.1')

    def test_filter_combination(self):
        # Filter: Source=Feodo AND Country=DE
        filters = {'source': 'Feodo', 'country': 'DE'}
        total, filtered, items = get_indicators_paginated(filters=filters)
        self.assertEqual(len(items), 1)
        self.assertEqual(items[0]['indicator'], '2.2.2.2')

if __name__ == '__main__':
    unittest.main()
