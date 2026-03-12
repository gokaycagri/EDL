import unittest
import os
import sys
from datetime import UTC, datetime

# Add path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '../')))

from threat_feed_aggregator.repositories.whitelist_repo import (
    add_whitelist_item,
    get_whitelist,
    remove_whitelist_item,
    add_api_blacklist_item,
    get_api_blacklist_items,
    remove_api_blacklist_item
)
from threat_feed_aggregator.database.connection import get_db_connection
from threat_feed_aggregator.database.schema import init_db

class TestCommentFields(unittest.TestCase):
    def setUp(self):
        init_db() # Ensure tables exist
        self.conn = get_db_connection()
        self.test_ip_safe = "1.2.3.4"
        self.test_ip_block = "5.6.7.8"
        # Cleanup before tests
        self._cleanup()

    def tearDown(self):
        self._cleanup()
        self.conn.close()

    def _cleanup(self):
        cur = self.conn.cursor()
        try:
            cur.execute("DELETE FROM whitelist WHERE item = %s", (self.test_ip_safe,))
            cur.execute("DELETE FROM api_blacklist WHERE item = %s", (self.test_ip_block,))
            self.conn.commit()
        except:
            # Fallback for SQLite if testing locally
            try:
                cur.execute("DELETE FROM whitelist WHERE item = ?", (self.test_ip_safe,))
                cur.execute("DELETE FROM api_blacklist WHERE item = ?", (self.test_ip_block,))
                self.conn.commit()
            except:
                pass

    def test_whitelist_description(self):
        """Verify that description is correctly saved in Safe List."""
        desc = "This is a trusted server for testing"
        success, msg = add_whitelist_item(self.test_ip_safe, description=desc, conn=self.conn)
        self.assertTrue(success)
        
        whitelist = get_whitelist(conn=self.conn)
        item = next((i for i in whitelist if i['item'] == self.test_ip_safe), None)
        
        self.assertIsNotNone(item)
        self.assertEqual(item['description'], desc)

    def test_blacklist_comment(self):
        """Verify that comment is correctly saved in Block List."""
        comment = "Suspicious activity detected during audit"
        success, msg = add_api_blacklist_item(self.test_ip_block, comment=comment, conn=self.conn)
        self.assertTrue(success)
        
        blacklist = get_api_blacklist_items(conn=self.conn)
        item = next((i for i in blacklist if i['item'] == self.test_ip_block), None)
        
        self.assertIsNotNone(item)
        self.assertEqual(item['comment'], comment)

if __name__ == '__main__':
    unittest.main()
