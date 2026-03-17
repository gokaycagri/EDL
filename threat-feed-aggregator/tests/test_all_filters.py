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

class TestAllFilters(unittest.TestCase):
    def setUp(self):
        # Use a temp file DB so all functions (including db_readonly) use the same DB
        self._db_fd, self._db_path = tempfile.mkstemp(suffix='.db')
        os.environ['TEST_DB_NAME'] = self._db_path
        os.environ['DB_TYPE'] = 'sqlite'

        import threat_feed_aggregator.database.connection as _conn_mod
        _conn_mod.DB_NAME = self._db_path

        init_db()

        from threat_feed_aggregator.database.connection import get_db_connection
        conn = get_db_connection()
        # Seed Data
        upsert_indicators_bulk([("1.1.1.1", "US", "ip"), ("2.2.2.2", "DE", "ip")], source_name="Feodo Tracker")
        upsert_indicators_bulk([("bad.com", "CN", "domain")], source_name="URLHaus")
        upsert_indicators_bulk([("phish.site", "TR", "url")], source_name="USOM")

        # Manually update scores
        conn.execute("UPDATE indicators SET risk_score = 95 WHERE indicator = '1.1.1.1'")
        conn.execute("UPDATE indicators SET risk_score = 50 WHERE indicator = '2.2.2.2'")
        conn.execute("UPDATE indicators SET risk_score = 80 WHERE indicator = 'bad.com'")
        conn.execute("UPDATE indicators SET risk_score = 30 WHERE indicator = 'phish.site'")
        conn.commit()
        conn.close()

    def tearDown(self):
        os.close(self._db_fd)
        os.remove(self._db_path)
        os.environ.pop('TEST_DB_NAME', None)

    def test_filter_source(self):
        _, _, items = get_indicators_paginated(filters={'source': 'Feodo'})
        self.assertEqual(len(items), 2)

        _, _, items = get_indicators_paginated(filters={'source': 'USOM'})
        self.assertEqual(len(items), 1)
        self.assertEqual(items[0]['indicator'], 'phish.site')

    def test_filter_tag(self):
        _, _, items = get_indicators_paginated(filters={'tag': 'Botnet'})
        self.assertEqual(len(items), 2) # Feodo maps to Botnet

        _, _, items = get_indicators_paginated(filters={'tag': 'Malware'})
        self.assertEqual(len(items), 1) # URLHaus maps to Malware

    def test_filter_type(self):
        _, _, items = get_indicators_paginated(filters={'type': 'ip'})
        self.assertEqual(len(items), 2)

        _, _, items = get_indicators_paginated(filters={'type': 'domain'})
        self.assertEqual(len(items), 1)

    def test_filter_country(self):
        _, _, items = get_indicators_paginated(filters={'country': 'US'})
        self.assertEqual(len(items), 1)
        self.assertEqual(items[0]['indicator'], '1.1.1.1')

    def test_filter_level(self):
        _, _, items = get_indicators_paginated(filters={'level': 'Critical'})
        self.assertEqual(len(items), 1) # 95

        _, _, items = get_indicators_paginated(filters={'level': 'Medium'})
        self.assertEqual(len(items), 1) # 50

    def test_filter_risk_score_operators(self):
        # Default >=
        _, _, items = get_indicators_paginated(filters={'risk_score': '80'})
        # Should match 80 and 95
        self.assertEqual(len(items), 2)

        # Explicit >=
        _, _, items = get_indicators_paginated(filters={'risk_score': '>=80'})
        self.assertEqual(len(items), 2)

        # Greater >
        _, _, items = get_indicators_paginated(filters={'risk_score': '>80'})
        self.assertEqual(len(items), 1) # Only 95

        # Less <
        _, _, items = get_indicators_paginated(filters={'risk_score': '<50'})
        self.assertEqual(len(items), 1) # Only 30

        # Equal =
        _, _, items = get_indicators_paginated(filters={'risk_score': '=50'})
        self.assertEqual(len(items), 1)

if __name__ == '__main__':
    unittest.main()
