import sqlite3
import logging
from datetime import datetime, timezone

DB_NAME = "threat_feed.db"

def get_db_connection():
    conn = sqlite3.connect(DB_NAME)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    """Initializes the database with the necessary tables."""
    conn = get_db_connection()
    try:
        conn.execute('''
            CREATE TABLE IF NOT EXISTS indicators (
                indicator TEXT PRIMARY KEY,
                last_seen TEXT NOT NULL
            )
        ''')
        conn.commit()
    except Exception as e:
        logging.error(f"Error initializing database: {e}")
    finally:
        conn.close()

def upsert_indicator(indicator):
    """Inserts a new indicator or updates the last_seen timestamp if it exists."""
    conn = get_db_connection()
    try:
        now_iso = datetime.now(timezone.utc).isoformat()
        conn.execute('''
            INSERT INTO indicators (indicator, last_seen)
            VALUES (?, ?)
            ON CONFLICT(indicator) DO UPDATE SET
                last_seen = excluded.last_seen
        ''', (indicator, now_iso))
        conn.commit()
    except Exception as e:
        logging.error(f"Error upserting indicator {indicator}: {e}")
    finally:
        conn.close()

def upsert_indicators_bulk(indicators):
    """Bulk upsert for a list of indicators."""
    conn = get_db_connection()
    try:
        now_iso = datetime.now(timezone.utc).isoformat()
        data = [(ind, now_iso) for ind in indicators]
        conn.executemany('''
            INSERT INTO indicators (indicator, last_seen)
            VALUES (?, ?)
            ON CONFLICT(indicator) DO UPDATE SET
                last_seen = excluded.last_seen
        ''', data)
        conn.commit()
    except Exception as e:
        logging.error(f"Error bulk upserting indicators: {e}")
    finally:
        conn.close()

def get_all_indicators():
    """Retrieves all indicators."""
    conn = get_db_connection()
    try:
        cursor = conn.execute('SELECT indicator, last_seen FROM indicators')
        return {row['indicator']: {'last_seen': row['last_seen']} for row in cursor.fetchall()}
    finally:
        conn.close()

def remove_old_indicators(lifetime_days):
    """Removes indicators older than the specified lifetime."""
    conn = get_db_connection()
    try:
        # Calculate the cutoff date
        # Note: We are comparing ISO format strings, which works for standard ISO 8601
        # providing they are all UTC. SQLite's date functions can also be used if we standardized on them.
        # For simplicity and consistency with previous JSON logic, we fetch and filter or use SQLite's datetime.
        # Let's use SQLite's datetime function for efficiency.
        
        cutoff_date = f"datetime('now', '-{lifetime_days} days')"
        
        # Since we store ISO strings (e.g., 2023-10-27T10:00:00+00:00), direct comparison with 
        # SQLite's 'now' (UTC) might be tricky if formats don't align perfectly.
        # A safer robust way without migrating all data format logic is to fetch and check in Python 
        # OR ensure we store standard format.
        # Let's stick to the previous logic style: fetch all, check in python, delete by ID. 
        # BUT for performance, SQL is better. 
        # Let's assume the previous code used `datetime.fromisoformat`. 
        
        # Optimizing: Let's fetch all, filter in Python (safe), then delete.
        # This avoids timezone mismatch issues in pure SQL if the stored string format varies.
        
        cursor = conn.execute('SELECT indicator, last_seen FROM indicators')
        to_delete = []
        now = datetime.now(timezone.utc)
        
        for row in cursor:
            try:
                last_seen = datetime.fromisoformat(row['last_seen'])
                if (now - last_seen).days > lifetime_days:
                    to_delete.append(row['indicator'])
            except ValueError:
                # If date format is bad, mark for deletion or log? Let's log.
                logging.warning(f"Invalid date format for {row['indicator']}: {row['last_seen']}")
                
        if to_delete:
            conn.executemany('DELETE FROM indicators WHERE indicator = ?', [(x,) for x in to_delete])
            conn.commit()
            
        return len(to_delete)

    except Exception as e:
        logging.error(f"Error removing old indicators: {e}")
        return 0
    finally:
        conn.close()

def get_unique_ip_count():
    conn = get_db_connection()
    try:
        cursor = conn.execute('SELECT COUNT(*) FROM indicators')
        return cursor.fetchone()[0]
    finally:
        conn.close()
