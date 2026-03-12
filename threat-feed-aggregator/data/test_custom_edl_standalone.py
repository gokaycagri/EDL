import unittest
import sqlite3
import json
import os
import sys
from datetime import datetime, UTC

# Add project root to path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

# Mock DATA_DIR before importing connection
import threat_feed_aggregator.config_manager
threat_feed_aggregator.config_manager.DATA_DIR = "." # Use current dir for test db

from threat_feed_aggregator.database.connection import get_db_connection, db_transaction, DB_WRITE_LOCK
from threat_feed_aggregator.database.schema import init_db
from threat_feed_aggregator.repositories.custom_list_repo import create_custom_list, get_all_custom_lists, get_custom_list_by_token, delete_custom_list
from threat_feed_aggregator.repositories.indicator_repo import upsert_indicators_bulk, get_sources_for_indicator, get_filtered_indicators_iter, recalculate_scores, get_all_indicators

class TestCustomEDL(unittest.TestCase):
    def setUp(self):
        # Use an in-memory DB for speed and isolation
        self.conn = sqlite3.connect(':memory:')
        self.conn.row_factory = sqlite3.Row
        
        # Initialize Schema
        init_db(self.conn)

    def tearDown(self):
        self.conn.close()

    def test_create_and_get_custom_list(self):
        name = "Test List"
        sources = ["Source A", "Source B"]
        types = ["ip"]
        fmt = "text"

        list_id, token = create_custom_list(name, sources, types, fmt, conn=self.conn)
        
        # Verify get_all
        lists = get_all_custom_lists(conn=self.conn)
        self.assertEqual(len(lists), 1)
        self.assertEqual(lists[0]['name'], name)
        self.assertEqual(lists[0]['token'], token)
        self.assertEqual(lists[0]['sources'], sources)

        # Verify get_by_token
        fetched = get_custom_list_by_token(token, conn=self.conn)
        self.assertIsNotNone(fetched)
        self.assertEqual(fetched['id'], list_id)

    def test_delete_custom_list(self):
        list_id, _ = create_custom_list("Del List", [], [], "text", conn=self.conn)
        self.assertTrue(delete_custom_list(list_id, conn=self.conn))
        self.assertEqual(len(get_all_custom_lists(conn=self.conn)), 0)

    def test_internal_search_logic(self):
        # 1. Seed Data
        indicators = [
            ("1.1.1.1", "US", "ip"),
            ("example.com", "US", "domain")
        ]
        upsert_indicators_bulk(indicators, source_name="Feed A", conn=self.conn)
        
        # Add duplicate to test history
        upsert_indicators_bulk([("1.1.1.1", "US", "ip")], source_name="Feed B", conn=self.conn)

        # 2. Test get_sources_for_indicator
        sources = get_sources_for_indicator("1.1.1.1", conn=self.conn)
        self.assertEqual(len(sources), 2)
        names = sorted([s['source_name'] for s in sources])
        self.assertEqual(names, ["Feed A", "Feed B"])

        # Test non-existent
        sources = get_sources_for_indicator("9.9.9.9", conn=self.conn)
        self.assertEqual(len(sources), 0)

    def test_filtered_indicators_iter(self):
        # Seed
        upsert_indicators_bulk([("1.1.1.1", "US", "ip")], source_name="Src1", conn=self.conn)
        upsert_indicators_bulk([("2.2.2.2", "US", "ip")], source_name="Src2", conn=self.conn)
        upsert_indicators_bulk([("3.3.3.3", "US", "ip")], source_name="Src1", conn=self.conn)

        # Test Filter
        iterator = get_filtered_indicators_iter(["Src1"], conn=self.conn)
        results = list(iterator)
        self.assertEqual(len(results), 2)
        ips = sorted([r['indicator'] for r in results])
        self.assertEqual(ips, ["1.1.1.1", "3.3.3.3"])

    def test_recalculate_scores(self):
        # Seed
        upsert_indicators_bulk([("1.1.1.1", "US", "ip")], source_name="HighConf", conn=self.conn)
        upsert_indicators_bulk([("1.1.1.1", "US", "ip")], source_name="LowConf", conn=self.conn)
        upsert_indicators_bulk([("2.2.2.2", "US", "ip")], source_name="LowConf", conn=self.conn)

        conf_map = {"HighConf": 90, "LowConf": 10}
        
        # 1. Test Full Recalculation
        recalculate_scores(conf_map, conn=self.conn)
        data = get_all_indicators(conn=self.conn)
        
        # 1.1.1.1 has 2 sources. Max(90, 10) + (2-1)*5 = 90 + 5 = 95
        self.assertEqual(data["1.1.1.1"]["risk_score"], 95)
        # 2.2.2.2 has 1 source. Max(10) + 0 = 10
        self.assertEqual(data["2.2.2.2"]["risk_score"], 10)

        # 2. Test Target Recalculation (Modify LowConf, Recalc HighConf should imply no change logic but actually target source filtering works on indicators OF that source)
        # Let's change LowConf to 50
        conf_map["LowConf"] = 50
        
        # Only recalc for HighConf source indicators (1.1.1.1 is in HighConf, 2.2.2.2 is NOT)
        # So 1.1.1.1 should update, 2.2.2.2 should NOT update even though LowConf changed map
        recalculate_scores(conf_map, conn=self.conn, target_source="HighConf")
        
        data = get_all_indicators(conn=self.conn)
        # 1.1.1.1 (in HighConf): Max(90, 50) + 5 = 95. (Wait, previous was 95. If LowConf was 50, it is still 95).
        # Let's change HighConf to 20
        conf_map["HighConf"] = 20
        recalculate_scores(conf_map, conn=self.conn, target_source="HighConf")
        
        data = get_all_indicators(conn=self.conn)
        # 1.1.1.1: Max(20, 50) + 5 = 55.
        self.assertEqual(data["1.1.1.1"]["risk_score"], 55)
        
        # 2.2.2.2 (Only in LowConf): Should NOT have been touched by query filtering for HighConf
        # Previous score 10.
        self.assertEqual(data["2.2.2.2"]["risk_score"], 10)

if __name__ == '__main__':
    unittest.main()
