import sqlite3
import logging
from datetime import datetime, timezone, timedelta
import os
import threading
from werkzeug.security import generate_password_hash, check_password_hash
from contextlib import contextmanager
from .config_manager import DATA_DIR

logger = logging.getLogger(__name__)

DB_NAME = os.path.join(DATA_DIR, "threat_feed.db")

# Global Lock for DB Writes
DB_WRITE_LOCK = threading.Lock()

def get_db_connection(timeout=30.0):
    conn = sqlite3.connect(DB_NAME, timeout=timeout)
    conn.execute('PRAGMA journal_mode=WAL;')
    conn.execute('PRAGMA foreign_keys=ON;') # Enable foreign keys
    conn.row_factory = sqlite3.Row
    return conn

@contextmanager
def db_transaction(conn=None):
    """
    Context manager for database transactions.
    If a connection is provided, it uses it (and does NOT close it).
    If no connection is provided, it creates a new one (and closes it).
    """
    should_close = False
    if conn is None:
        conn = get_db_connection()
        should_close = True
    try:
        yield conn
    finally:
        if should_close:
            conn.close()

def init_db(conn=None):
    with DB_WRITE_LOCK:
        with db_transaction(conn) as db:
            try:
                # 1. Indicators Table (Expanded)
                db.execute('''
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
                cursor = db.execute("PRAGMA table_info(indicators)")
                columns = [info[1] for info in cursor.fetchall()]
                if 'country' not in columns: db.execute('ALTER TABLE indicators ADD COLUMN country TEXT')
                if 'type' not in columns: db.execute("ALTER TABLE indicators ADD COLUMN type TEXT NOT NULL DEFAULT 'ip'")
                if 'risk_score' not in columns: db.execute("ALTER TABLE indicators ADD COLUMN risk_score INTEGER DEFAULT 50")
                if 'source_count' not in columns: db.execute("ALTER TABLE indicators ADD COLUMN source_count INTEGER DEFAULT 1")

                # 2. Indicator Sources Table (New: Many-to-Many Relationship)
                db.execute('''
                    CREATE TABLE IF NOT EXISTS indicator_sources (
                        indicator TEXT,
                        source_name TEXT,
                        last_seen TEXT,
                        PRIMARY KEY (indicator, source_name),
                        FOREIGN KEY(indicator) REFERENCES indicators(indicator) ON DELETE CASCADE
                    )
                ''')

                # Whitelist Table
                db.execute('''
                    CREATE TABLE IF NOT EXISTS whitelist (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        item TEXT NOT NULL UNIQUE,
                        description TEXT,
                        added_at TEXT NOT NULL
                    )
                ''')

                # API Blacklist Table (For SOAR Integration)
                db.execute('''
                    CREATE TABLE IF NOT EXISTS api_blacklist (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        item TEXT NOT NULL UNIQUE,
                        type TEXT NOT NULL DEFAULT 'ip',
                        comment TEXT,
                        added_at TEXT NOT NULL
                    )
                ''')

                # Users Table
                db.execute('''
                    CREATE TABLE IF NOT EXISTS users (
                        username TEXT PRIMARY KEY,
                        password_hash TEXT NOT NULL
                    )
                ''')

                # Job History Table
                db.execute('''
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

                # Stats History Table (New for Trend Graphs)
                db.execute('''
                    CREATE TABLE IF NOT EXISTS stats_history (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        timestamp TEXT NOT NULL,
                        total_indicators INTEGER,
                        ip_count INTEGER,
                        domain_count INTEGER,
                        url_count INTEGER
                    )
                ''')
                
                db.commit()
            except Exception as e:
                logger.error(f"Error initializing database: {e}")

# ... (Job History functions) ...
def log_job_start(source_name, conn=None):
    with DB_WRITE_LOCK:
        with db_transaction(conn) as db:
            try:
                start_time = datetime.now(timezone.utc).isoformat()
                cursor = db.execute(
                    'INSERT INTO job_history (source_name, start_time, status) VALUES (?, ?, ?)',
                    (source_name, start_time, 'running')
                )
                db.commit()
                return cursor.lastrowid
            except Exception as e:
                logger.error(f"Error logging job start: {e}")
                return None

def log_job_end(job_id, status, items_processed=0, message=None, conn=None):
    if not job_id: return
    with DB_WRITE_LOCK:
        with db_transaction(conn) as db:
            try:
                end_time = datetime.now(timezone.utc).isoformat()
                db.execute('''
                    UPDATE job_history 
                    SET end_time = ?, status = ?, items_processed = ?, message = ?
                    WHERE id = ?
                ''', (end_time, status, items_processed, message, job_id))
                db.commit()
            except Exception as e:
                logger.error(f"Error logging job end: {e}")

def get_job_history(limit=50, conn=None):
    with db_transaction(conn) as db:
        cursor = db.execute('SELECT * FROM job_history ORDER BY start_time DESC LIMIT ?', (limit,))
        return [dict(row) for row in cursor.fetchall()]

def clear_job_history(conn=None):
    with DB_WRITE_LOCK:
        with db_transaction(conn) as db:
            try:
                db.execute('DELETE FROM job_history')
                db.commit()
                return True
            except Exception as e:
                logger.error(f"Error clearing job history: {e}")
                return False

# ... (User Mgmt functions) ...
def set_admin_password(password, conn=None):
    with DB_WRITE_LOCK:
        with db_transaction(conn) as db:
            try:
                hashed_password = generate_password_hash(password)
                db.execute('INSERT OR REPLACE INTO users (username, password_hash) VALUES (?, ?)', 
                             ('admin', hashed_password))
                db.commit()
                return True, "Admin password set/updated."
            except Exception as e:
                return False, str(e)

def get_admin_password_hash(conn=None):
    with db_transaction(conn) as db:
        cursor = db.execute("SELECT password_hash FROM users WHERE username = 'admin'")
        result = cursor.fetchone()
        return result['password_hash'] if result else None

def check_admin_credentials(password, conn=None):
    stored_hash = get_admin_password_hash(conn)
    if stored_hash and check_password_hash(stored_hash, password):
        return True
    return False

# --- SCORING & UPSERT LOGIC (UPDATED) ---

def upsert_indicators_bulk(indicators, source_name="Unknown", conn=None):
    """
    Bulk upsert with scoring logic.
    indicators: list of (indicator, country, type)
    """
    with DB_WRITE_LOCK:
        with db_transaction(conn) as db:
            try:
                now_iso = datetime.now(timezone.utc).isoformat()
                
                # Step 1: Insert OR Ignore into indicators (to ensure existence)
                data_for_indicators = []
                for item, country, indicator_type in indicators:
                    data_for_indicators.append((item, now_iso, country, indicator_type))

                # Use INSERT OR IGNORE to add new ones. 
                # We update last_seen separately or via conflict if we want to update metadata.
                # Let's use upsert to update country/last_seen.
                db.executemany('''
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
                
                db.executemany('''
                    INSERT OR REPLACE INTO indicator_sources (indicator, source_name, last_seen)
                    VALUES (?, ?, ?)
                ''', data_for_sources)
                
                db.commit()
            except Exception as e:
                logger.error(f"Error bulk upserting indicators: {e}")
                raise 

def recalculate_scores(source_confidence_map=None, conn=None):
    """
    Recalculates source_count and risk_score for ALL indicators based on source confidence.
    Formula: Base Score (Max Confidence of sources) + Overlap Bonus.
    
    Args:
        source_confidence_map (dict): {source_name: confidence_score (int)}. Default confidence is 50.
    """
    if source_confidence_map is None:
        source_confidence_map = {}

    with DB_WRITE_LOCK:
        with db_transaction(conn) as db:
            try:
                # 1. Update source_count (Always keep this accurate)
                db.execute('''
                    UPDATE indicators
                    SET source_count = (
                        SELECT COUNT(*) 
                        FROM indicator_sources 
                        WHERE indicator_sources.indicator = indicators.indicator
                    )
                ''')
                
                # 2. Update risk_score using Temporary Table for Confidences
                # Create temp table
                db.execute('CREATE TEMPORARY TABLE IF NOT EXISTS temp_source_conf (name TEXT PRIMARY KEY, score INTEGER)')
                db.execute('DELETE FROM temp_source_conf')
                
                # Prepare data (default to 50 if not provided)
                data_to_insert = [(name, score) for name, score in source_confidence_map.items()]
                if data_to_insert:
                    db.executemany('INSERT INTO temp_source_conf (name, score) VALUES (?, ?)', data_to_insert)
                
                # The complex update query
                db.execute('''
                    UPDATE indicators
                    SET risk_score = (
                        SELECT MIN(100, 
                            MAX(COALESCE(sc.score, 50)) + ((indicators.source_count - 1) * 5)
                        )
                        FROM indicator_sources src
                        LEFT JOIN temp_source_conf sc ON src.source_name = sc.name
                        WHERE src.indicator = indicators.indicator
                    )
                    WHERE EXISTS (SELECT 1 FROM indicator_sources WHERE indicator = indicators.indicator)
                ''')
                
                db.commit()
                logger.info(f"Scores recalculated successfully with map: {source_confidence_map}")
            except Exception as e:
                logger.error(f"Error recalculating scores: {e}")

# ... (Rest of functions) ...
def get_all_indicators(conn=None):
    with db_transaction(conn) as db:
        cursor = db.execute('SELECT indicator, last_seen, country, type, risk_score, source_count FROM indicators')
        return {row['indicator']: {
            'last_seen': row['last_seen'], 
            'country': row['country'], 
            'type': row['type'],
            'risk_score': row['risk_score'],
            'source_count': row['source_count']
        } for row in cursor.fetchall()}

def remove_old_indicators(source_retention_map=None, default_retention_days=30, conn=None):
    """
    Removes indicators based on per-source retention policies.
    """
    if source_retention_map is None:
        source_retention_map = {}

    with DB_WRITE_LOCK:
        with db_transaction(conn) as db:
            try:
                now = datetime.now(timezone.utc)
                total_deleted_sources = 0
                
                # 1. Clean up indicator_sources per source
                cursor = db.execute("SELECT DISTINCT source_name FROM indicator_sources")
                db_sources = [row['source_name'] for row in cursor.fetchall()]

                for source in db_sources:
                    days = source_retention_map.get(source, default_retention_days)
                    cutoff_date = now - timedelta(days=days)
                    
                    # Delete old associations for this source
                    cur = db.execute(
                        "DELETE FROM indicator_sources WHERE source_name = ? AND last_seen < ?", 
                        (source, cutoff_date.isoformat())
                    )
                    total_deleted_sources += cur.rowcount
                
                # 2. Clean up Orphans (Indicators with no sources left)
                cur = db.execute('''
                    DELETE FROM indicators 
                    WHERE indicator NOT IN (SELECT DISTINCT indicator FROM indicator_sources)
                ''')
                orphans_deleted = cur.rowcount

                if total_deleted_sources > 0 or orphans_deleted > 0:
                    db.commit()
                    logger.info(f"Cleanup: Removed {total_deleted_sources} expired source links and {orphans_deleted} orphaned indicators.")
                
                return orphans_deleted
            except Exception as e:
                logger.error(f"Error removing old indicators: {e}")
                return 0

def get_unique_indicator_count(indicator_type=None, conn=None):
    with db_transaction(conn) as db:
        if indicator_type:
            cursor = db.execute('SELECT COUNT(*) FROM indicators WHERE type = ?', (indicator_type,))
        else:
            cursor = db.execute('SELECT COUNT(*) FROM indicators')
        return cursor.fetchone()[0]

def get_indicator_counts_by_type(conn=None):
    with db_transaction(conn) as db:
        cursor = db.execute('SELECT type, COUNT(*) as count FROM indicators GROUP BY type')
        return {row['type']: row['count'] for row in cursor.fetchall()}

def get_country_stats(conn=None):
    with db_transaction(conn) as db:
        try:
            cursor = db.execute('''
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

# --- Whitelist Functions ---
def add_whitelist_item(item, description="", conn=None):
    with DB_WRITE_LOCK:
        with db_transaction(conn) as db:
            try:
                now_iso = datetime.now(timezone.utc).isoformat()
                db.execute('INSERT INTO whitelist (item, description, added_at) VALUES (?, ?, ?)', 
                             (item.strip(), description, now_iso))
                db.commit()
                return True, "Item added to whitelist."
            except sqlite3.IntegrityError:
                return False, "Item already in whitelist."
            except Exception as e:
                logger.error(f"Error adding to whitelist: {e}")
                return False, str(e)

def get_whitelist(conn=None):
    with db_transaction(conn) as db:
        cursor = db.execute('SELECT * FROM whitelist ORDER BY added_at DESC')
        return [dict(row) for row in cursor.fetchall()]

def remove_whitelist_item(item_id, conn=None):
    with DB_WRITE_LOCK:
        with db_transaction(conn) as db:
            try:
                db.execute('DELETE FROM whitelist WHERE id = ?', (item_id,))
                db.commit()
                return True
            except Exception as e:
                logger.error(f"Error removing from whitelist: {e}")
                return False

# --- API Blacklist Functions ---
def add_api_blacklist_item(item, item_type='ip', comment="", conn=None):
    with DB_WRITE_LOCK:
        with db_transaction(conn) as db:
            try:
                now_iso = datetime.now(timezone.utc).isoformat()
                db.execute('INSERT INTO api_blacklist (item, type, comment, added_at) VALUES (?, ?, ?, ?)', 
                             (item.strip(), item_type, comment, now_iso))
                db.commit()
                return True, "Item added to blacklist."
            except sqlite3.IntegrityError:
                return False, "Item already in blacklist."
            except Exception as e:
                logger.error(f"Error adding to api_blacklist: {e}")
                return False, str(e)

def get_api_blacklist_items(conn=None):
    with db_transaction(conn) as db:
        cursor = db.execute('SELECT * FROM api_blacklist ORDER BY added_at DESC')
        return [dict(row) for row in cursor.fetchall()]

def remove_api_blacklist_item(item, conn=None):
    with DB_WRITE_LOCK:
        with db_transaction(conn) as db:
            try:
                # Can remove by ID or exact item string
                if isinstance(item, int) or (isinstance(item, str) and item.isdigit()):
                    db.execute('DELETE FROM api_blacklist WHERE id = ?', (item,))
                else:
                    db.execute('DELETE FROM api_blacklist WHERE item = ?', (item,))
                db.commit()
                return True
            except Exception as e:
                logger.error(f"Error removing from api_blacklist: {e}")
                return False

def delete_whitelisted_indicators(items_to_delete, conn=None):
    with DB_WRITE_LOCK:
        with db_transaction(conn) as db:
            try:
                if items_to_delete:
                    placeholders = ','.join(['?' for _ in items_to_delete])
                    db.execute(f'DELETE FROM indicators WHERE indicator IN ({placeholders})', items_to_delete)
                    # Also delete from sources
                    db.execute(f'DELETE FROM indicator_sources WHERE indicator IN ({placeholders})', items_to_delete)
                    db.commit()
                    return True
                return False
            except Exception as e:
                logger.error(f"Error deleting whitelisted indicators: {e}")
                return False

def save_historical_stats(conn=None):
    """Captures current stats and saves to history."""
    with DB_WRITE_LOCK:
        with db_transaction(conn) as db:
            try:
                cursor = db.execute("SELECT COUNT(*) FROM indicators")
                total = cursor.fetchone()[0]
                
                cursor = db.execute("SELECT type, COUNT(*) FROM indicators GROUP BY type")
                counts = {row[0]: row[1] for row in cursor.fetchall()}
                
                ip_count = counts.get('ip', 0) + counts.get('cidr', 0)
                domain_count = counts.get('domain', 0)
                url_count = counts.get('url', 0)
                
                now_iso = datetime.now(timezone.utc).isoformat()
                
                db.execute('''
                    INSERT INTO stats_history (timestamp, total_indicators, ip_count, domain_count, url_count)
                    VALUES (?, ?, ?, ?, ?)
                ''', (now_iso, total, ip_count, domain_count, url_count))
                
                db.commit()
                logger.info("Saved historical stats for trend analysis.")
            except Exception as e:
                logger.error(f"Error saving stats history: {e}")

def get_historical_stats(days=30, conn=None):
    with db_transaction(conn) as db:
        cutoff = (datetime.now(timezone.utc) - timedelta(days=days)).isoformat()
        
        cursor = db.execute('''
            SELECT timestamp, total_indicators, ip_count, domain_count, url_count 
            FROM stats_history 
            WHERE timestamp > ? 
            ORDER BY timestamp ASC
        ''', (cutoff,))
        return [dict(row) for row in cursor.fetchall()]
