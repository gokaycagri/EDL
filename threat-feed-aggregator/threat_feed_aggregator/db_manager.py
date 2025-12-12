import sqlite3
import logging
from datetime import datetime, timezone
import os

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DATA_DIR = os.path.join(BASE_DIR, "data")
DB_NAME = os.path.join(DATA_DIR, "threat_feed.db")

def get_db_connection():
    conn = sqlite3.connect(DB_NAME)
    conn.execute('PRAGMA journal_mode=WAL;')
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    """Initializes the database with the necessary tables."""
    conn = get_db_connection()
    try:
        # Create indicators table if not exists
        conn.execute('''
            CREATE TABLE IF NOT EXISTS indicators (
                indicator TEXT PRIMARY KEY,
                last_seen TEXT NOT NULL
            )
        ''')
        
        # Check if country column exists, if not add it
        cursor = conn.execute("PRAGMA table_info(indicators)")
        columns = [info[1] for info in cursor.fetchall()]
        if 'country' not in columns:
            try:
                conn.execute('ALTER TABLE indicators ADD COLUMN country TEXT')
                logging.info("Added 'country' column to indicators table.")
            except Exception as e:
                logging.error(f"Error adding country column: {e}")

        # Create Whitelist Table
        conn.execute('''
            CREATE TABLE IF NOT EXISTS whitelist (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                item TEXT NOT NULL UNIQUE,
                description TEXT,
                added_at TEXT NOT NULL
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
    """
    Bulk upsert for a list of indicators.
    Indicators can be a list of strings (IPs) or tuples (IP, Country).
    """
    conn = get_db_connection()
    try:
        now_iso = datetime.now(timezone.utc).isoformat()
        data = []
        for item in indicators:
            if isinstance(item, tuple):
                # (indicator, country)
                data.append((item[0], now_iso, item[1]))
            else:
                # indicator only
                data.append((item, now_iso, None))

        conn.executemany('''
            INSERT INTO indicators (indicator, last_seen, country)
            VALUES (?, ?, ?)
            ON CONFLICT(indicator) DO UPDATE SET
                last_seen = excluded.last_seen,
                country = COALESCE(excluded.country, indicators.country)
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
        cursor = conn.execute('SELECT indicator, last_seen FROM indicators')
        to_delete = []
        now = datetime.now(timezone.utc)
        
        for row in cursor:
            try:
                last_seen = datetime.fromisoformat(row['last_seen'])
                if (now - last_seen).days > lifetime_days:
                    to_delete.append(row['indicator'])
            except ValueError:
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

def get_country_stats():
    """Returns a list of dictionaries (country_code, count) ordered by count descending."""
    conn = get_db_connection()
    try:
        # Group by country, handle NULLs as 'Unknown'
        cursor = conn.execute('''
            SELECT COALESCE(country, 'Unknown') as country_code, COUNT(*) as count 
            FROM indicators 
            GROUP BY country_code 
            ORDER BY count DESC
            LIMIT 10
        ''')
        return [dict(row) for row in cursor.fetchall()]
    except Exception as e:
        logging.error(f"Error getting country stats: {e}")
        return []
    finally:
        conn.close()

# --- Whitelist Functions ---

def add_whitelist_item(item, description=""):
    conn = get_db_connection()
    try:
        now_iso = datetime.now(timezone.utc).isoformat()
        conn.execute('INSERT INTO whitelist (item, description, added_at) VALUES (?, ?, ?)', 
                     (item.strip(), description, now_iso))
        conn.commit()
        return True, "Item added to whitelist."
    except sqlite3.IntegrityError:
        return False, "Item already in whitelist."
    except Exception as e:
        logging.error(f"Error adding to whitelist: {e}")
        return False, str(e)
    finally:
        conn.close()

def get_whitelist():
    conn = get_db_connection()
    try:
        cursor = conn.execute('SELECT * FROM whitelist ORDER BY added_at DESC')
        return [dict(row) for row in cursor.fetchall()]
    finally:
        conn.close()

def remove_whitelist_item(item_id):
    conn = get_db_connection()
    try:
        conn.execute('DELETE FROM whitelist WHERE id = ?', (item_id,))
        conn.commit()
        return True
    except Exception as e:
        logging.error(f"Error removing from whitelist: {e}")
        return False
    finally:
        conn.close()

def delete_whitelisted_indicators(indicators_to_delete):
    """
    Deletes indicators from the main table that match the provided list of indicators.
    """
    conn = get_db_connection()
    try:
        if indicators_to_delete:
            placeholders = ','.join(['?' for _ in indicators_to_delete])
            conn.execute(f'DELETE FROM indicators WHERE indicator IN ({placeholders})', indicators_to_delete)
            conn.commit()
            return True
        return False
    except Exception as e:
        logging.error(f"Error deleting whitelisted indicators: {e}")
        return False
    finally:
        conn.close()

