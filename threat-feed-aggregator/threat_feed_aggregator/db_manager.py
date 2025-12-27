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

                # Indexes for Performance
                db.execute('CREATE INDEX IF NOT EXISTS idx_indicators_type ON indicators(type)')
                db.execute('CREATE INDEX IF NOT EXISTS idx_indicator_sources_name_seen ON indicator_sources(source_name, last_seen)')

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

                # --- Admin Profiles (RBAC) ---
                db.execute('''
                    CREATE TABLE IF NOT EXISTS admin_profiles (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        name TEXT NOT NULL UNIQUE,
                        description TEXT,
                        permissions TEXT NOT NULL -- JSON string: {"module": "access_level"}
                    )
                ''')

                # --- LDAP Group Mappings ---
                db.execute('''
                    CREATE TABLE IF NOT EXISTS ldap_group_mappings (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        group_dn TEXT NOT NULL UNIQUE,
                        profile_id INTEGER NOT NULL,
                        FOREIGN KEY(profile_id) REFERENCES admin_profiles(id) ON DELETE CASCADE
                    )
                ''')

                # Seed Default Profiles FIRST (to satisfy FK constraints when migrating users)
                cursor = db.execute("SELECT COUNT(*) FROM admin_profiles")
                if cursor.fetchone()[0] == 0:
                    import json
                    # 1. Super_User (Full Access)
                    db.execute('INSERT INTO admin_profiles (name, description, permissions) VALUES (?, ?, ?)',
                               ('Super_User', 'Full access to all modules', json.dumps({
                                   "dashboard": "rw", "system": "rw", "tools": "rw"
                               })))
                    # 2. Standard_User (Limited System Access)
                    db.execute('INSERT INTO admin_profiles (name, description, permissions) VALUES (?, ?, ?)',
                               ('Standard_User', 'Can manage feeds but not system settings', json.dumps({
                                   "dashboard": "rw", "system": "r", "tools": "rw"
                               })))
                    # 3. Read_Only (View Only)
                    db.execute('INSERT INTO admin_profiles (name, description, permissions) VALUES (?, ?, ?)',
                               ('Read_Only', 'View access only', json.dumps({
                                   "dashboard": "r", "system": "r", "tools": "r"
                               })))

                # Users Table Migration (Add profile_id)
                cursor = db.execute("PRAGMA table_info(users)")
                user_columns = [info[1] for info in cursor.fetchall()]
                if 'profile_id' not in user_columns:
                    try:
                        # SQLite limitation: Cannot add REFERENCES in ALTER TABLE easily.
                        # Adding column without FK constraint for migration.
                        db.execute('ALTER TABLE users ADD COLUMN profile_id INTEGER DEFAULT 1')
                    except Exception as ex:
                        logger.error(f"Migration error (profile_id): {ex}")
                    
                    # Ensure admin has correct profile
                    db.execute("UPDATE users SET profile_id = 1 WHERE username = 'admin'")
                
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

# --- Local User Management (Generic) ---

def get_all_users(conn=None):
    """Returns a list of all local users with their profile names."""
    with db_transaction(conn) as db:
        try:
            cursor = db.execute('''
                SELECT u.username, p.name as profile_name 
                FROM users u 
                LEFT JOIN admin_profiles p ON u.profile_id = p.id 
                ORDER BY u.username ASC
            ''')
            results = [dict(row) for row in cursor.fetchall()]
            logger.info(f"Fetched {len(results)} users: {[r['username'] for r in results]}")
            return results
        except Exception as e:
            logger.error(f"Error fetching users: {e}")
            return []

def add_local_user(username, password, conn=None):
    """Adds a new local user."""
    with DB_WRITE_LOCK:
        with db_transaction(conn) as db:
            try:
                hashed_password = generate_password_hash(password)
                db.execute('INSERT INTO users (username, password_hash) VALUES (?, ?)', 
                             (username, hashed_password))
                db.commit()
                return True, f"User {username} added."
            except sqlite3.IntegrityError:
                return False, "Username already exists."
            except Exception as e:
                return False, str(e)

def update_local_user_password(username, password, conn=None):
    """Updates password for an existing user."""
    with DB_WRITE_LOCK:
        with db_transaction(conn) as db:
            try:
                hashed_password = generate_password_hash(password)
                cursor = db.execute('UPDATE users SET password_hash = ? WHERE username = ?', 
                                  (hashed_password, username))
                db.commit()
                if cursor.rowcount > 0:
                    return True, "Password updated."
                else:
                    return False, "User not found."
            except Exception as e:
                return False, str(e)

def delete_local_user(username, conn=None):
    """Deletes a local user (prevents deleting 'admin')."""
    if username == 'admin':
        return False, "Cannot delete the default admin account."
        
    with DB_WRITE_LOCK:
        with db_transaction(conn) as db:
            try:
                cursor = db.execute('DELETE FROM users WHERE username = ?', (username,))
                db.commit()
                if cursor.rowcount > 0:
                    return True, "User deleted."
                else:
                    return False, "User not found."
            except Exception as e:
                return False, str(e)

def verify_local_user(username, password, conn=None):
    """Verifies credentials for any local user."""
    with db_transaction(conn) as db:
        cursor = db.execute("SELECT password_hash FROM users WHERE username = ?", (username,))
        result = cursor.fetchone()
        if result and check_password_hash(result['password_hash'], password):
            return True
        return False

def local_user_exists(username, conn=None):
    """Checks if a user exists in the local database."""
    with db_transaction(conn) as db:
        cursor = db.execute("SELECT 1 FROM users WHERE username = ?", (username,))
        return cursor.fetchone() is not None

# --- SCORING & UPSERT LOGIC (UPDATED) ---

def upsert_indicators_bulk(indicators, source_name="Unknown", conn=None):
    """
    Highly optimized bulk upsert with scoring logic.
    indicators: list of (indicator, country, type)
    """
    with DB_WRITE_LOCK:
        with db_transaction(conn) as db:
            try:
                now_iso = datetime.now(timezone.utc).isoformat()
                
                # Speed Optimization: Use a temporary table for bulk operations
                db.execute('CREATE TEMPORARY TABLE IF NOT EXISTS temp_bulk_indicators (indicator TEXT, country TEXT, type TEXT)')
                db.execute('DELETE FROM temp_bulk_indicators')
                
                db.executemany('INSERT INTO temp_bulk_indicators VALUES (?, ?, ?)', indicators)

                # Step 1: Bulk Upsert into main indicators table
                # Using INSERT OR REPLACE for compatibility with older SQLite versions
                db.execute(f'''
                    INSERT OR REPLACE INTO indicators (indicator, last_seen, country, type, risk_score, source_count)
                    SELECT indicator, ?, country, type, 50, 1 FROM temp_bulk_indicators
                ''', (now_iso,))

                # Step 2: Bulk Update indicator_sources
                db.execute(f'''
                    INSERT OR REPLACE INTO indicator_sources (indicator, source_name, last_seen)
                    SELECT indicator, ?, ? FROM temp_bulk_indicators
                ''', (source_name, now_iso))
                
                db.commit()
            except Exception as e:
                logger.error(f"Error bulk upserting indicators: {e}")
                raise 

def clean_database_vacuum(conn=None):
    """Performs VACUUM to shrink DB size and optimize indexes."""
    with db_transaction(conn) as db:
        db.execute('VACUUM')
        logger.info("Database vacuumed and optimized.")
def get_all_indicators_iter(conn=None):
    """
    Generator that yields indicators one by one to save memory.
    Ideal for EDL generation with large datasets.
    """
    with db_transaction(conn) as db:
        cursor = db.execute('SELECT indicator, last_seen, country, type, risk_score, source_count FROM indicators')
        for row in cursor:
            yield row

def recalculate_scores(source_confidence_map=None, conn=None):
    """
    Optimized: Recalculates risk scores using a more efficient SQL structure.
    """
    if source_confidence_map is None:
        source_confidence_map = {}

    with DB_WRITE_LOCK:
        with db_transaction(conn) as db:
            try:
                # 1. Update source_count accurately
                db.execute('''
                    UPDATE indicators
                    SET source_count = (
                        SELECT COUNT(*) 
                        FROM indicator_sources 
                        WHERE indicator_sources.indicator = indicators.indicator
                    )
                ''')
                
                # 2. Use a temporary table for confidence scores to join against
                db.execute('CREATE TEMPORARY TABLE IF NOT EXISTS temp_source_conf (name TEXT PRIMARY KEY, score INTEGER)')
                db.execute('DELETE FROM temp_source_conf')
                
                data_to_insert = [(name, score) for name, score in source_confidence_map.items()]
                if data_to_insert:
                    db.executemany('INSERT INTO temp_source_conf VALUES (?, ?)', data_to_insert)
                
                # 3. Optimized calculation using a single UPDATE with a correlated subquery
                # Formula: Max(Confidence) + (Overlap Bonus)
                db.execute('''
                    UPDATE indicators
                    SET risk_score = (
                        SELECT MIN(100, MAX(COALESCE(sc.score, 50)) + ((indicators.source_count - 1) * 5))
                        FROM indicator_sources src
                        LEFT JOIN temp_source_conf sc ON src.source_name = sc.name
                        WHERE src.indicator = indicators.indicator
                    )
                    WHERE EXISTS (SELECT 1 FROM indicator_sources WHERE indicator = indicators.indicator)
                ''')
                
                db.commit()
                logger.info(f"Scores recalculated efficiently for all indicators.")
            except Exception as e:
                logger.error(f"Error recalculating scores: {e}")
                db.rollback()

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
    if not item:
        return False, "Item is empty."
    
    from .utils import validate_indicator
    is_valid, _ = validate_indicator(item)
    if not is_valid:
        return False, f"'{item}' is not a valid IP, CIDR, or Domain/URL."

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
    if not item:
        return False, "Item is empty."

    from .utils import validate_indicator
    is_valid, _ = validate_indicator(item)
    if not is_valid:
        return False, f"'{item}' is not a valid IP, CIDR, or Domain/URL."

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

# --- Admin Profile Management ---

def get_admin_profiles(conn=None):
    with db_transaction(conn) as db:
        cursor = db.execute('SELECT * FROM admin_profiles ORDER BY id ASC')
        return [dict(row) for row in cursor.fetchall()]

def add_admin_profile(name, description, permissions, conn=None):
    import json
    with DB_WRITE_LOCK:
        with db_transaction(conn) as db:
            try:
                db.execute('INSERT INTO admin_profiles (name, description, permissions) VALUES (?, ?, ?)',
                           (name, description, json.dumps(permissions)))
                db.commit()
                return True, "Profile added."
            except sqlite3.IntegrityError:
                return False, "Profile name already exists."
            except Exception as e:
                return False, str(e)

def delete_admin_profile(profile_id, conn=None):
    if profile_id in (1, 2, 3): # Protect default profiles
        return False, "Cannot delete default profiles."
    
    with DB_WRITE_LOCK:
        with db_transaction(conn) as db:
            try:
                # Reassign users to Read_Only (id=3) before deleting
                db.execute('UPDATE users SET profile_id = 3 WHERE profile_id = ?', (profile_id,))
                db.execute('DELETE FROM admin_profiles WHERE id = ?', (profile_id,))
                db.commit()
                return True, "Profile deleted."
            except Exception as e:
                return False, str(e)

def update_admin_profile(profile_id, description, permissions, conn=None):
    if profile_id == 1: # Protect Super_User permissions
        return False, "Cannot modify Super_User permissions."
        
    import json
    with DB_WRITE_LOCK:
        with db_transaction(conn) as db:
            try:
                db.execute('UPDATE admin_profiles SET description = ?, permissions = ? WHERE id = ?',
                           (description, json.dumps(permissions), profile_id))
                db.commit()
                return True, "Profile updated."
            except Exception as e:
                return False, str(e)

def get_user_permissions(username, conn=None):
    """Retrieves the permissions dict for a specific user."""
    import json
    with db_transaction(conn) as db:
        cursor = db.execute('''
            SELECT p.permissions 
            FROM users u 
            JOIN admin_profiles p ON u.profile_id = p.id 
            WHERE u.username = ?
        ''', (username,))
        row = cursor.fetchone()
        if row:
            try:
                return json.loads(row['permissions'])
            except:
                return {} # Fallback
        return {} # Default no permissions

# --- LDAP Group Mappings ---

def get_ldap_group_mappings(conn=None):
    with db_transaction(conn) as db:
        cursor = db.execute('''
            SELECT m.id, m.group_dn, p.name as profile_name 
            FROM ldap_group_mappings m
            JOIN admin_profiles p ON m.profile_id = p.id
            ORDER BY m.id ASC
        ''')
        return [dict(row) for row in cursor.fetchall()]

def add_ldap_group_mapping(group_dn, profile_id, conn=None):
    with DB_WRITE_LOCK:
        with db_transaction(conn) as db:
            try:
                db.execute('INSERT INTO ldap_group_mappings (group_dn, profile_id) VALUES (?, ?)',
                           (group_dn.strip(), profile_id))
                db.commit()
                return True, "Mapping added."
            except sqlite3.IntegrityError:
                return False, "Group DN already mapped."
            except Exception as e:
                return False, str(e)

def delete_ldap_group_mapping(mapping_id, conn=None):
    with DB_WRITE_LOCK:
        with db_transaction(conn) as db:
            try:
                db.execute('DELETE FROM ldap_group_mappings WHERE id = ?', (mapping_id,))
                db.commit()
                return True, "Mapping deleted."
            except Exception as e:
                return False, str(e)

def get_profile_by_ldap_groups(user_groups, conn=None):
    """
    Checks user groups against mappings and returns the best profile_id.
    Prioritizes profile_id 1 (Super_User) if multiple groups match.
    """
    with db_transaction(conn) as db:
        try:
            cursor = db.execute('SELECT group_dn, profile_id FROM ldap_group_mappings')
            mappings = cursor.fetchall()
            
            normalized_user_groups = [g.lower() for g in user_groups]
            matched_profile_ids = []
            
            for mapping in mappings:
                if mapping['group_dn'].lower() in normalized_user_groups:
                    matched_profile_ids.append(mapping['profile_id'])
            
            if not matched_profile_ids:
                return None
                
            # If any matched profile is Super_User (1), return it
            if 1 in matched_profile_ids:
                return 1
                
            # Otherwise return the first matched (or logic can be added for 2 > 3 etc)
            return matched_profile_ids[0]
        except Exception as e:
            logger.error(f"Error checking LDAP group mappings: {e}")
        
        return None
