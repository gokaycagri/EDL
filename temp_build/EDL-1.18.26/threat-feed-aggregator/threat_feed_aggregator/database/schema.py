import json
import logging

from ..database.connection import DB_WRITE_LOCK, db_transaction, DB_TYPE

logger = logging.getLogger(__name__)

def init_db(conn=None):
    logger.info("Starting init_db...")
    
    with db_transaction(conn) as db:
        try:
            logger.info("Creating tables...")
            pk_def = "INTEGER PRIMARY KEY AUTOINCREMENT"
            if DB_TYPE == 'postgres':
                pk_def = "SERIAL PRIMARY KEY"

            # 1. Indicators Table
            db.execute(f'''
                CREATE TABLE IF NOT EXISTS indicators (
                    indicator TEXT PRIMARY KEY,
                    last_seen TEXT NOT NULL,
                    country TEXT,
                    type TEXT NOT NULL DEFAULT 'ip',
                    risk_score INTEGER DEFAULT 50, 
                    source_count INTEGER DEFAULT 1
                )
            ''')
            logger.info("Table indicators checked.")

            if DB_TYPE == 'sqlite':
                cursor = db.execute("PRAGMA table_info(indicators)")
                columns = [info[1] for info in cursor.fetchall()]
                if 'country' not in columns: db.execute('ALTER TABLE indicators ADD COLUMN country TEXT')
                if 'type' not in columns: db.execute("ALTER TABLE indicators ADD COLUMN type TEXT NOT NULL DEFAULT 'ip'")
                if 'risk_score' not in columns: db.execute("ALTER TABLE indicators ADD COLUMN risk_score INTEGER DEFAULT 50")
                if 'source_count' not in columns: db.execute("ALTER TABLE indicators ADD COLUMN source_count INTEGER DEFAULT 1")

            # 2. Indicator Sources Table
            db.execute('''
                CREATE TABLE IF NOT EXISTS indicator_sources (
                    indicator TEXT,
                    source_name TEXT,
                    last_seen TEXT,
                    PRIMARY KEY (indicator, source_name),
                    FOREIGN KEY(indicator) REFERENCES indicators(indicator) ON DELETE CASCADE
                )
            ''')
            logger.info("Table indicator_sources checked.")

            # Indexes commented out here - moved to create_indexes_safely
            # db.execute('CREATE INDEX IF NOT EXISTS idx_indicators_type ON indicators(type)')
            # ...

            # Whitelist Table
            db.execute(f'''
                CREATE TABLE IF NOT EXISTS whitelist (
                    id {pk_def},
                    item TEXT NOT NULL UNIQUE,
                    type TEXT NOT NULL DEFAULT 'ip',
                    description TEXT,
                    added_at TEXT NOT NULL
                )
            ''')

            # Migration for Whitelist (Add 'type' column if missing)
            if DB_TYPE == 'sqlite':
                cursor = db.execute("PRAGMA table_info(whitelist)")
                columns = [info[1] for info in cursor.fetchall()]
                if 'type' not in columns: db.execute("ALTER TABLE whitelist ADD COLUMN type TEXT NOT NULL DEFAULT 'ip'")
            else:
                # Postgres Column Checks (Attempt add and ignore error)
                try:
                    db.execute('ALTER TABLE whitelist ADD COLUMN IF NOT EXISTS type TEXT NOT NULL DEFAULT \'ip\'')
                except:
                    pass

            # API Blacklist Table
            db.execute(f'''
                CREATE TABLE IF NOT EXISTS api_blacklist (
                    id {pk_def},
                    item TEXT NOT NULL UNIQUE,
                    type TEXT NOT NULL DEFAULT 'ip',
                    comment TEXT,
                    added_at TEXT NOT NULL,
                    expires_at TEXT
                )
            ''')

            # Migration for api_blacklist (Add 'expires_at' if missing)
            if DB_TYPE == 'sqlite':
                cursor = db.execute("PRAGMA table_info(api_blacklist)")
                columns = [info[1] for info in cursor.fetchall()]
                if 'expires_at' not in columns: db.execute("ALTER TABLE api_blacklist ADD COLUMN expires_at TEXT")
            else:
                try:
                    db.execute('ALTER TABLE api_blacklist ADD COLUMN IF NOT EXISTS expires_at TEXT')
                except:
                    pass

            # Users Table
            db.execute('''
                CREATE TABLE IF NOT EXISTS users (
                    username TEXT PRIMARY KEY,
                    password_hash TEXT NOT NULL,
                    profile_id INTEGER DEFAULT 1,
                    mfa_secret TEXT
                )
            ''')

            # Job History Table
            db.execute(f'''
                CREATE TABLE IF NOT EXISTS job_history (
                    id {pk_def},
                    source_name TEXT NOT NULL,
                    start_time TEXT NOT NULL,
                    end_time TEXT,
                    status TEXT NOT NULL, 
                    items_processed INTEGER DEFAULT 0,
                    message TEXT
                )
            ''')

            # Stats History Table
            db.execute(f'''
                CREATE TABLE IF NOT EXISTS stats_history (
                    id {pk_def},
                    timestamp TEXT NOT NULL,
                    total_indicators INTEGER,
                    ip_count INTEGER,
                    domain_count INTEGER,
                    url_count INTEGER
                )
            ''')

            # Custom EDL Lists
            db.execute(f'''
                CREATE TABLE IF NOT EXISTS custom_lists (
                    id {pk_def},
                    name TEXT NOT NULL,
                    token TEXT NOT NULL UNIQUE,
                    sources TEXT NOT NULL, 
                    types TEXT NOT NULL,   
                    format TEXT NOT NULL DEFAULT 'text',
                    created_at TEXT NOT NULL
                )
            ''')

            # Admin Profiles
            db.execute(f'''
                CREATE TABLE IF NOT EXISTS admin_profiles (
                    id {pk_def},
                    name TEXT NOT NULL UNIQUE,
                    description TEXT,
                    permissions TEXT NOT NULL
                )
            ''')

            # LDAP Group Mappings
            db.execute(f'''
                CREATE TABLE IF NOT EXISTS ldap_group_mappings (
                    id {pk_def},
                    group_dn TEXT NOT NULL UNIQUE,
                    profile_id INTEGER NOT NULL,
                    FOREIGN KEY(profile_id) REFERENCES admin_profiles(id) ON DELETE CASCADE
                )
            ''')

            # DNS Resolution Cache
            db.execute('''
                CREATE TABLE IF NOT EXISTS dns_resolution_cache (
                    domain TEXT PRIMARY KEY,
                    resolved_ips TEXT,
                    last_resolved TEXT
                )
            ''')
            # Index moved to create_indexes_safely
            # Ensure columns for context/comment exist (Migration for existing DBs)
            try:
                # Whitelist description
                db.execute("SELECT description FROM whitelist LIMIT 1")
            except Exception:
                logger.info("Adding missing 'description' column to whitelist table.")
                if DB_TYPE == 'postgres':
                    db.execute("ALTER TABLE whitelist ADD COLUMN IF NOT EXISTS description TEXT")
                else:
                    db.execute("ALTER TABLE whitelist ADD COLUMN description TEXT")

            try:
                # Blacklist comment
                db.execute("SELECT comment FROM api_blacklist LIMIT 1")
            except Exception:
                logger.info("Adding missing 'comment' column to api_blacklist table.")
                if DB_TYPE == 'postgres':
                    db.execute("ALTER TABLE api_blacklist ADD COLUMN IF NOT EXISTS comment TEXT")
                else:
                    db.execute("ALTER TABLE api_blacklist ADD COLUMN comment TEXT")

            logger.info("All tables and columns checked.")

            # Seed Default Profiles
            count_query = "SELECT COUNT(*) FROM admin_profiles"
            cursor = db.execute(count_query)
            if cursor.fetchone()[0] == 0:
                insert_cmd = 'INSERT INTO admin_profiles (name, description, permissions) VALUES (?, ?, ?)'
                if DB_TYPE == 'postgres':
                    insert_cmd = insert_cmd.replace('?', '%s')
                
                db.execute(insert_cmd,
                           ('Super_User', 'Full access to all modules', json.dumps({
                               "dashboard": "rw", "system": "rw", "tools": "rw"
                           })))
                db.execute(insert_cmd,
                           ('Standard_User', 'Can manage feeds but not system settings', json.dumps({
                               "dashboard": "rw", "system": "r", "tools": "rw"
                           })))
                db.execute(insert_cmd,
                           ('Read_Only', 'View access only', json.dumps({
                               "dashboard": "r", "system": "r", "tools": "r"
                           })))

            # Users Table Migration logic (SQLite only)
            if DB_TYPE == 'sqlite':
                cursor = db.execute("PRAGMA table_info(users)")
                user_columns = [info[1] for info in cursor.fetchall()]
                
                if 'profile_id' not in user_columns:
                    try:
                        db.execute('ALTER TABLE users ADD COLUMN profile_id INTEGER DEFAULT 1')
                        db.execute("UPDATE users SET profile_id = 1 WHERE username = 'admin'")
                    except Exception as ex:
                        logger.error(f"Migration error (profile_id): {ex}")

                if 'mfa_secret' not in user_columns:
                    try:
                        db.execute('ALTER TABLE users ADD COLUMN mfa_secret TEXT')
                    except Exception as ex:
                        logger.error(f"Migration error (mfa_secret): {ex}")

        except Exception as e:
            logger.error(f"Error initializing database: {e}")

def create_indexes_safely(conn=None):
    """
    Creates indexes. Designed to be run in a background thread to avoid blocking startup.
    """
    logger.info("Starting background index creation/verification...")
    with db_transaction(conn) as db:
        try:
            # Indexes for Indicators
            db.execute('CREATE INDEX IF NOT EXISTS idx_indicators_type ON indicators(type)')
            db.execute('CREATE INDEX IF NOT EXISTS idx_indicators_country ON indicators(country)')
            
            # Indexes for Sources
            db.execute('CREATE INDEX IF NOT EXISTS idx_indicator_sources_name_seen ON indicator_sources(source_name, last_seen)')
            
            # Indexes for DNS Cache
            db.execute('CREATE INDEX IF NOT EXISTS idx_dns_cache_last_resolved ON dns_resolution_cache(last_resolved)')
            
            logger.info("Background index creation completed.")
        except Exception as e:
            logger.error(f"Error creating indexes: {e}")