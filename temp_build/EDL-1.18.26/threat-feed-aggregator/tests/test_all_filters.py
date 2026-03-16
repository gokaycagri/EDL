import unittest
import sqlite3
import sys
import os

# Add project root to path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

# Mock DATA_DIR
import threat_feed_aggregator.config_manager
threat_feed_aggregator.config_manager.DATA_DIR = "."

from threat_feed_aggregator.database.schema import init_db
from threat_feed_aggregator.repositories.indicator_repo import upsert_indicators_bulk, get_indicators_paginated

class TestAllFilters(unittest.TestCase):
    def setUp(self):
        self.conn = sqlite3.connect(':memory:')
        self.conn.row_factory = sqlite3.Row
        init_db(self.conn)
        
        # Seed Data
        # 1. Feodo (Botnet) -> IP: 1.1.1.1 (Score 95 - Critical), 2.2.2.2 (Score 50 - Medium)
        # 2. URLHaus (Malware) -> Domain: bad.com (Score 80 - High)
        # 3. USOM (Phishing) -> URL: phish.site (Score 30 - Low)
        upsert_indicators_bulk([("1.1.1.1", "US", "ip"), ("2.2.2.2", "DE", "ip")], source_name="Feodo Tracker", conn=self.conn)
        upsert_indicators_bulk([("bad.com", "CN", "domain")], source_name="URLHaus", conn=self.conn)
        upsert_indicators_bulk([("phish.site", "TR", "url")], source_name="USOM", conn=self.conn)
        
        # Manually update scores
        self.conn.execute("UPDATE indicators SET risk_score = 95 WHERE indicator = '1.1.1.1'")
        self.conn.execute("UPDATE indicators SET risk_score = 50 WHERE indicator = '2.2.2.2'")
        self.conn.execute("UPDATE indicators SET risk_score = 80 WHERE indicator = 'bad.com'")
        self.conn.execute("UPDATE indicators SET risk_score = 30 WHERE indicator = 'phish.site'")
        self.conn.commit()

    def tearDown(self):
        self.conn.close()

    def test_filter_source(self):
        _, _, items = get_indicators_paginated(filters={'source': 'Feodo'}, conn=self.conn)
        self.assertEqual(len(items), 2)
        
        _, _, items = get_indicators_paginated(filters={'source': 'USOM'}, conn=self.conn)
        self.assertEqual(len(items), 1)
        self.assertEqual(items[0]['indicator'], 'phish.site')

    def test_filter_tag(self):
        _, _, items = get_indicators_paginated(filters={'tag': 'Botnet'}, conn=self.conn)
        self.assertEqual(len(items), 2) # Feodo maps to Botnet
        
        _, _, items = get_indicators_paginated(filters={'tag': 'Malware'}, conn=self.conn)
        self.assertEqual(len(items), 1) # URLHaus maps to Malware

    def test_filter_type(self):
        _, _, items = get_indicators_paginated(filters={'type': 'ip'}, conn=self.conn)
        self.assertEqual(len(items), 2)
        
        _, _, items = get_indicators_paginated(filters={'type': 'domain'}, conn=self.conn)
        self.assertEqual(len(items), 1)

    def test_filter_country(self):
        _, _, items = get_indicators_paginated(filters={'country': 'US'}, conn=self.conn)
        self.assertEqual(len(items), 1)
        self.assertEqual(items[0]['indicator'], '1.1.1.1')

    def test_filter_level(self):
        _, _, items = get_indicators_paginated(filters={'level': 'Critical'}, conn=self.conn)
        self.assertEqual(len(items), 1) # 95
        
        _, _, items = get_indicators_paginated(filters={'level': 'Medium'}, conn=self.conn)
        self.assertEqual(len(items), 1) # 50

    def test_filter_risk_score_operators(self):
        # Default >=
        _, _, items = get_indicators_paginated(filters={'risk_score': '80'}, conn=self.conn)
        # Should match 80 and 95
        self.assertEqual(len(items), 2)
        
        # Explicit >=
        _, _, items = get_indicators_paginated(filters={'risk_score': '>=80'}, conn=self.conn)
        self.assertEqual(len(items), 2)
        
        # Greater >
        _, _, items = get_indicators_paginated(filters={'risk_score': '>80'}, conn=self.conn)
        self.assertEqual(len(items), 1) # Only 95
        
        # Less <
        _, _, items = get_indicators_paginated(filters={'risk_score': '<50'}, conn=self.conn)
        self.assertEqual(len(items), 1) # Only 30
        
        # Equal =
        _, _, items = get_indicators_paginated(filters={'risk_score': '=50'}, conn=self.conn)
        self.assertEqual(len(items), 1)

if __name__ == '__main__':
    unittest.main()
