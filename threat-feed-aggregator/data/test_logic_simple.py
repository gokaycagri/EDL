import unittest
from datetime import UTC, datetime, timedelta
import os
import sys

# Add path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '../')))

from threat_feed_aggregator.repositories.whitelist_repo import (
    add_api_blacklist_item, 
    remove_expired_blacklist_items,
    get_api_blacklist_items
)
from threat_feed_aggregator.database.connection import get_db_connection

class TestSimple(unittest.TestCase):
    def test_logic(self):
        print("Starting test...")
        conn = get_db_connection()
        print("Got connection")
        
        test_ip = "1.1.1.1"
        expired_at = (datetime.now(UTC) - timedelta(hours=1)).isoformat()
        
        print("Adding item...")
        add_api_blacklist_item(test_ip, comment="Expired", expires_at=expired_at, conn=conn)
        print("Item added")
        
        print("Cleaning up...")
        deleted = remove_expired_blacklist_items(conn=conn)
        print(f"Deleted: {deleted}")
        
        conn.close()
        print("Done")

if __name__ == '__main__':
    unittest.main()
