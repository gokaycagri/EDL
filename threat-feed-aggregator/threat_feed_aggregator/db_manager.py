import sqlite3
import logging
from datetime import datetime, timezone
import os
from werkzeug.security import generate_password_hash, check_password_hash

logger = logging.getLogger(__name__)

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
                last_seen TEXT NOT NULL,
                country TEXT,
                type TEXT NOT NULL DEFAULT 'ip'
            )
        ''')
        
        # Check schemas (simplified for brevity, ensuring columns exist)
        cursor = conn.execute("PRAGMA table_info(indicators)")
        columns = [info[1] for info in cursor.fetchall()]
        if 'country' not in columns:
            try: conn.execute('ALTER TABLE indicators ADD COLUMN country TEXT')
            except Exception: pass
        if 'type' not in columns:
            try: conn.execute("ALTER TABLE indicators ADD COLUMN type TEXT NOT NULL DEFAULT 'ip'")
            except Exception: pass

        # Create Whitelist Table
        conn.execute('''
            CREATE TABLE IF NOT EXISTS whitelist (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                item TEXT NOT NULL UNIQUE,
                description TEXT,
                added_at TEXT NOT NULL
            )
        ''')

        # Create Users Table
        conn.execute('''
            CREATE TABLE IF NOT EXISTS users (
                username TEXT PRIMARY KEY,
                password_hash TEXT NOT NULL
            )
        ''')

        # Create Job History Table (NEW)
        conn.execute('''
            CREATE TABLE IF NOT EXISTS job_history (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                source_name TEXT NOT NULL,
                start_time TEXT NOT NULL,
                end_time TEXT,
                status TEXT NOT NULL, -- 'running', 'success', 'failure'
                items_processed INTEGER DEFAULT 0,
                message TEXT
            )
        ''')
        
        conn.commit()
    except Exception as e:
        logger.error(f"Error initializing database: {e}")
    finally:
        conn.close()

# --- Job History Functions (NEW) ---

def log_job_start(source_name):
    """Starts a new job log entry."""
    conn = get_db_connection()
    try:
        start_time = datetime.now(timezone.utc).isoformat()
        cursor = conn.execute(
            'INSERT INTO job_history (source_name, start_time, status) VALUES (?, ?, ?)',
            (source_name, start_time, 'running')
        )
        conn.commit()
        return cursor.lastrowid
    except Exception as e:
        logger.error(f"Error logging job start: {e}")
        return None
    finally:
        conn.close()

def log_job_end(job_id, status, items_processed=0, message=None):
    """Updates a job log entry with completion details."""
    if not job_id:
        return
    conn = get_db_connection()
    try:
        end_time = datetime.now(timezone.utc).isoformat()
        conn.execute('''
            UPDATE job_history 
            SET end_time = ?, status = ?, items_processed = ?, message = ?
            WHERE id = ?
        ''', (end_time, status, items_processed, message, job_id))
        conn.commit()
    except Exception as e:
        logger.error(f"Error logging job end: {e}")
    finally:
        conn.close()

def get_job_history(limit=50):
    """Retrieves recent job history."""
    conn = get_db_connection()
    try:
        cursor = conn.execute('SELECT * FROM job_history ORDER BY start_time DESC LIMIT ?', (limit,))
        return [dict(row) for row in cursor.fetchall()]
    finally:
        conn.close()

# --- User Management Functions ---
def set_admin_password(password):
    conn = get_db_connection()
    try:
        hashed_password = generate_password_hash(password)
        conn.execute('INSERT OR REPLACE INTO users (username, password_hash) VALUES (?, ?)', 
                     ('admin', hashed_password))
        conn.commit()
        return True, "Admin password set/updated."
    except Exception as e:
        logger.error(f"Error setting admin password: {e}")
        return False, str(e)
    finally:
        conn.close()

def get_admin_password_hash():
    conn = get_db_connection()
    try:
        cursor = conn.execute("SELECT password_hash FROM users WHERE username = 'admin'")
        result = cursor.fetchone()
        return result['password_hash'] if result else None
    finally:
        conn.close()

def check_admin_credentials(password):
    stored_hash = get_admin_password_hash()
    if stored_hash and check_password_hash(stored_hash, password):
        return True
    return False

def upsert_indicators_bulk(indicators):
    conn = get_db_connection()
    try:
        now_iso = datetime.now(timezone.utc).isoformat()
        data = []
        for item, country, indicator_type in indicators:
            data.append((item, now_iso, country, indicator_type))

        conn.executemany('''
            INSERT INTO indicators (indicator, last_seen, country, type)
            VALUES (?, ?, ?, ?)
            ON CONFLICT(indicator) DO UPDATE SET
                last_seen = excluded.last_seen,
                country = COALESCE(excluded.country, indicators.country),
                type = excluded.type
        ''', data)
        conn.commit()
    except Exception as e:
        logger.error(f"Error bulk upserting indicators: {e}")
        raise # Re-raise to catch in aggregator
    finally:
        conn.close()

def get_all_indicators():
    conn = get_db_connection()
    try:
        cursor = conn.execute('SELECT indicator, last_seen, country, type FROM indicators')
        return {row['indicator']: {'last_seen': row['last_seen'], 'country': row['country'], 'type': row['type']} for row in cursor.fetchall()}
    finally:
        conn.close()

def remove_old_indicators(lifetime_days):
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
                pass
                
        if to_delete:
            conn.executemany('DELETE FROM indicators WHERE indicator = ?', [(x,) for x in to_delete])
            conn.commit()
            
        return len(to_delete)
    except Exception as e:
        logger.error(f"Error removing old indicators: {e}")
        return 0
    finally:
        conn.close()

def get_unique_indicator_count(indicator_type=None):
    conn = get_db_connection()
    try:
        if indicator_type:
            cursor = conn.execute('SELECT COUNT(*) FROM indicators WHERE type = ?', (indicator_type,))
        else:
            cursor = conn.execute('SELECT COUNT(*) FROM indicators')
        return cursor.fetchone()[0]
    finally:
        conn.close()

def get_indicator_counts_by_type():
    conn = get_db_connection()
    try:
        cursor = conn.execute('SELECT type, COUNT(*) as count FROM indicators GROUP BY type')
        return {row['type']: row['count'] for row in cursor.fetchall()}
    finally:
        conn.close()

def get_country_stats():
    conn = get_db_connection()
    try:
        cursor = conn.execute('''
            SELECT COALESCE(country, 'Unknown') as country_code, COUNT(*) as count 
            FROM indicators 
            WHERE type = 'ip'
            GROUP BY country_code 
            ORDER BY count DESC
            LIMIT 10
        ''')
        return [dict(row) for row in cursor.fetchall()]
    except Exception as e:
        logger.error(f"Error getting country stats: {e}")
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
        logger.error(f"Error adding to whitelist: {e}")
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
        logger.error(f"Error removing from whitelist: {e}")
        return False
    finally:
        conn.close()

def delete_whitelisted_indicators(items_to_delete):
    conn = get_db_connection()
    try:
        if items_to_delete:
            placeholders = ','.join(['?' for _ in items_to_delete])
            conn.execute(f'DELETE FROM indicators WHERE indicator IN ({placeholders})', items_to_delete)
            conn.commit()
            return True
        return False
    except Exception as e:
        logger.error(f"Error deleting whitelisted indicators: {e}")
        return False
    finally:
        conn.close()