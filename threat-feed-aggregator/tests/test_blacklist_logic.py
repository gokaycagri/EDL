import unittest
from datetime import UTC, datetime, timedelta
import os
import sys
import sqlite3

# Add path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '../')))

from threat_feed_aggregator.repositories.whitelist_repo import (
    add_api_blacklist_item, 
    remove_expired_blacklist_items,
    get_api_blacklist_items
)
from threat_feed_aggregator.database.connection import get_db_connection, DB_TYPE

class TestBlacklistLogic(unittest.TestCase):
    def setUp(self):
        # We use the real DB connection but we'll use a transaction that we rollback
        # Or better, since we are testing repo functions, we can use a temporary in-memory SQLite for logic testing
        # But the app is configured for Postgres in the environment.
        # Let's test against the actual DB but clean up.
        self.conn = get_db_connection()
        # Clean up any existing test data if necessary, but we'll use unique names
        self.test_ip_expired = "99.99.99.99"
        self.test_ip_valid = "88.88.88.88"

    def tearDown(self):
        # Manual cleanup
        cur = self.conn.cursor()
        try:
            # Using ? for consistency if the wrapper handles it, but repo uses ?
            # Actually, the repo functions handle the connection.
            cur.execute("DELETE FROM api_blacklist WHERE item IN ('99.99.99.99', '88.88.88.88')")
            self.conn.commit()
        finally:
            # cur.close() - if exists
            pass
        self.conn.close()

    def test_expiration_logic(self):
        """Test that expired blacklist items are correctly removed."""
        # 1. Add an expired item (past date)
        expired_at = (datetime.now(UTC) - timedelta(hours=1)).isoformat()
        add_api_blacklist_item(self.test_ip_expired, comment="Expired", expires_at=expired_at, conn=self.conn)
        
        # 2. Add a valid item (future date)
        valid_until = (datetime.now(UTC) + timedelta(hours=1)).isoformat()
        add_api_blacklist_item(self.test_ip_valid, comment="Valid", expires_at=valid_until, conn=self.conn)
        
        # 3. Verify they are both in DB
        items = get_api_blacklist_items(conn=self.conn)
        item_ips = [i['item'] for i in items]
        self.assertIn(self.test_ip_expired, item_ips)
        self.assertIn(self.test_ip_valid, item_ips)
        
        # 4. Run cleanup
        deleted_count = remove_expired_blacklist_items(conn=self.conn)
        self.assertGreaterEqual(deleted_count, 1)
        
        # 5. Verify expired is gone, valid remains
        items_after = get_api_blacklist_items(conn=self.conn)
        item_ips_after = [i['item'] for i in items_after]
        self.assertNotIn(self.test_ip_expired, item_ips_after)
        self.assertIn(self.test_ip_valid, item_ips_after)

    def test_rejects_private_ipv4(self):
        """Private RFC1918 IPs must never be accepted into API blacklist."""
        success, msg = add_api_blacklist_item("10.0.0.1", comment="Should be rejected", conn=self.conn)
        self.assertFalse(success)
        self.assertIn("RFC1918", msg)

if __name__ == '__main__':
    unittest.main()
