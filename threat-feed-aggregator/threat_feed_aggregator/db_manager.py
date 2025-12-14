import sqlite3
import logging
from datetime import datetime, timezone
import os
import threading
from werkzeug.security import generate_password_hash, check_password_hash

logger = logging.getLogger(__name__)

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DATA_DIR = os.path.join(BASE_DIR, "data")
DB_NAME = os.path.join(DATA_DIR, "threat_feed.db")

# Global Lock for DB Writes
DB_WRITE_LOCK = threading.Lock()

def get_db_connection(timeout=30.0):
    conn = sqlite3.connect(DB_NAME, timeout=timeout)
    conn.execute('PRAGMA journal_mode=WAL;')
    conn.execute('PRAGMA foreign_keys=ON;') # Enable foreign keys
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    with DB_WRITE_LOCK:
        conn = get_db_connection()
        try:
            # 1. Indicators Table (Expanded)
            conn.execute('''
                CREATE TABLE IF NOT EXISTS indicators (
                    indicator TEXT PRIMARY KEY,
                    last_seen TEXT NOT NULL,
                    country TEXT,
                    type TEXT NOT NULL DEFAULT 'ip',
                    risk_score INTEGER DEFAULT 50, -- New: Risk Score
                    source_count INTEGER DEFAULT 1 -- New: Source Count
                )
            ''')
            
            # Schema Migration for existing tables
            cursor = conn.execute("PRAGMA table_info(indicators)")
            columns = [info[1] for info in cursor.fetchall()]
            if 'country' not in columns: conn.execute('ALTER TABLE indicators ADD COLUMN country TEXT')
            if 'type' not in columns: conn.execute("ALTER TABLE indicators ADD COLUMN type TEXT NOT NULL DEFAULT 'ip'")
            if 'risk_score' not in columns: conn.execute("ALTER TABLE indicators ADD COLUMN risk_score INTEGER DEFAULT 50")
            if 'source_count' not in columns: conn.execute("ALTER TABLE indicators ADD COLUMN source_count INTEGER DEFAULT 1")

            # 2. Indicator Sources Table (New: Many-to-Many Relationship)
            conn.execute('''
                CREATE TABLE IF NOT EXISTS indicator_sources (
                    indicator TEXT,
                    source_name TEXT,
                    last_seen TEXT,
                    PRIMARY KEY (indicator, source_name),
                    FOREIGN KEY(indicator) REFERENCES indicators(indicator) ON DELETE CASCADE
                )
            ''')

            # Whitelist Table
            conn.execute('''
                CREATE TABLE IF NOT EXISTS whitelist (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    item TEXT NOT NULL UNIQUE,
                    description TEXT,
                    added_at TEXT NOT NULL
                )
            ''')

            # Users Table
            conn.execute('''
                CREATE TABLE IF NOT EXISTS users (
                    username TEXT PRIMARY KEY,
                    password_hash TEXT NOT NULL
                )
            ''')

            # Job History Table
            conn.execute('''
                CREATE TABLE IF NOT EXISTS job_history (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    source_name TEXT NOT NULL,
                    start_time TEXT NOT NULL,
                    end_time TEXT,
                    status TEXT NOT NULL, 
                    items_processed INTEGER DEFAULT 0,
                    message TEXT
                )
            ''')
            
            conn.commit()
        except Exception as e:
            logger.error(f"Error initializing database: {e}")
        finally:
            conn.close()

# ... (Job History functions remain same) ...
def log_job_start(source_name):
    with DB_WRITE_LOCK:
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
    if not job_id: return
    with DB_WRITE_LOCK:
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
    conn = get_db_connection()
    try:
        cursor = conn.execute('SELECT * FROM job_history ORDER BY start_time DESC LIMIT ?', (limit,))
        return [dict(row) for row in cursor.fetchall()]
    finally:
        conn.close()

def clear_job_history():
    with DB_WRITE_LOCK:
        conn = get_db_connection()
        try:
            conn.execute('DELETE FROM job_history')
            conn.commit()
            return True
        except Exception as e:
            logger.error(f"Error clearing job history: {e}")
            return False
        finally:
            conn.close()

# ... (User Mgmt functions remain same) ...
def set_admin_password(password):
    with DB_WRITE_LOCK:
        conn = get_db_connection()
        try:
            hashed_password = generate_password_hash(password)
            conn.execute('INSERT OR REPLACE INTO users (username, password_hash) VALUES (?, ?)', 
                         ('admin', hashed_password))
            conn.commit()
            return True, "Admin password set/updated."
        except Exception as e:
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

# --- SCORING & UPSERT LOGIC (UPDATED) ---

def upsert_indicators_bulk(indicators, source_name="Unknown"):
    """
    Bulk upsert with scoring logic.
    indicators: list of (indicator, country, type)
    """
    with DB_WRITE_LOCK:
        conn = get_db_connection()
        try:
            now_iso = datetime.now(timezone.utc).isoformat()
            
            # 1. Upsert into indicators table
            # Logic: If exists, update last_seen. Country/Type if NULL.
            # We don't increment source_count here directly, we calculate it from indicator_sources table or increment if new source.
            # For simplicity and performance in bulk, we'll do a two-step process.
            
            # Step 1: Insert OR Ignore into indicators (to ensure existence)
            # We initialize with score 50. Updates happen later.
            data_for_indicators = []
            for item, country, indicator_type in indicators:
                data_for_indicators.append((item, now_iso, country, indicator_type))

            # Use INSERT OR IGNORE to add new ones. 
            # We update last_seen separately or via conflict if we want to update metadata.
            # Let's use upsert to update country/last_seen.
            conn.executemany('''
                INSERT INTO indicators (indicator, last_seen, country, type, risk_score, source_count)
                VALUES (?, ?, ?, ?, 50, 1)
                ON CONFLICT(indicator) DO UPDATE SET
                    last_seen = excluded.last_seen,
                    country = COALESCE(excluded.country, indicators.country),
                    type = excluded.type
            ''', data_for_indicators)

            # Step 2: Update indicator_sources table
            data_for_sources = []
            for item, _, _ in indicators:
                data_for_sources.append((item, source_name, now_iso))
            
            conn.executemany('''
                INSERT OR REPLACE INTO indicator_sources (indicator, source_name, last_seen)
                VALUES (?, ?, ?)
            ''', data_for_sources)

            # Step 3: Recalculate Score and Source Count for affected indicators
            # This is expensive to do one-by-one. 
            # Optimization: We can do it in a single SQL update for the batch.
            # Score = 50 + (source_count - 1) * 10. Max 100.
            
            # We need to update indicators where indicator is in our batch
            # and set source_count = (SELECT COUNT(*) FROM indicator_sources WHERE indicator=...)
            
            # Creating a temp table or using IN clause with many items might be slow.
            # But for 5000 items batch, it should be fine.
            
            # Let's try to update source_count first
            # SQLite specific optimization for bulk updates based on another table is tricky without temp table.
            
            # Simplified approach: We assume that if we inserted into indicator_sources, count might change.
            # We can run a periodic "Score Recalculation" job instead of doing it real-time for every batch to save DB IO.
            # OR, we do a simple increment if it's a new source for this indicator? Hard to know if it's new without query.
            
            # DECISION: For performance, we will NOT recalculate score on every batch insert.
            # We will implement a `recalculate_scores()` function that runs at the end of `aggregate_single_source` 
            # or `main`.
            
            conn.commit()
        except Exception as e:
            logger.error(f"Error bulk upserting indicators: {e}")
            raise 
        finally:
            conn.close()

def recalculate_scores():
    """
    Recalculates source_count and risk_score for ALL indicators.
    Should be called periodically (e.g. after a feed update).
    """
    with DB_WRITE_LOCK:
        conn = get_db_connection()
        try:
            # 1. Update source_count
            conn.execute('''
                UPDATE indicators
                SET source_count = (
                    SELECT COUNT(*) 
                    FROM indicator_sources 
                    WHERE indicator_sources.indicator = indicators.indicator
                )
            ''')
            
            # 2. Update risk_score
            # Base 50 + (Count-1)*10. Min 0, Max 100.
            conn.execute('''
                UPDATE indicators
                SET risk_score = MIN(100, 50 + ((source_count - 1) * 10))
            ''')
            
            conn.commit()
            logger.info("Scores recalculated successfully.")
        except Exception as e:
            logger.error(f"Error recalculating scores: {e}")
        finally:
            conn.close()

# ... (Rest of functions: get_all_indicators, remove_old_indicators etc. remain same) ...
def get_all_indicators():
    conn = get_db_connection()
    try:
        cursor = conn.execute('SELECT indicator, last_seen, country, type, risk_score, source_count FROM indicators')
        return {row['indicator']: {
            'last_seen': row['last_seen'], 
            'country': row['country'], 
            'type': row['type'],
            'risk_score': row['risk_score'],
            'source_count': row['source_count']
        } for row in cursor.fetchall()}
    finally:
        conn.close()

def remove_old_indicators(lifetime_days):
    with DB_WRITE_LOCK:
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
                # Cascade delete will handle indicator_sources if FK is enabled, but manual delete is safer if not
                conn.executemany('DELETE FROM indicator_sources WHERE indicator = ?', [(x,) for x in to_delete])
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
    with DB_WRITE_LOCK:
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
    with DB_WRITE_LOCK:
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
    with DB_WRITE_LOCK:
        conn = get_db_connection()
        try:
            if items_to_delete:
                placeholders = ','.join(['?' for _ in items_to_delete])
                conn.execute(f'DELETE FROM indicators WHERE indicator IN ({placeholders})', items_to_delete)
                # Also delete from sources
                conn.execute(f'DELETE FROM indicator_sources WHERE indicator IN ({placeholders})', items_to_delete)
                conn.commit()
                return True
            return False
        except Exception as e:
            logger.error(f"Error deleting whitelisted indicators: {e}")
            return False
        finally:
            conn.close()