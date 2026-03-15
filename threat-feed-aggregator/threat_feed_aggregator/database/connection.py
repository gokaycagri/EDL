import logging
import os
import sqlite3
import threading
from contextlib import contextmanager

try:
    import psycopg2
    from psycopg2 import pool  # noqa: F401
    from psycopg2.extras import DictCursor
except ImportError:
    psycopg2 = None

from ..config_manager import DATA_DIR
from ..constants import DB_TIMEOUT

logger = logging.getLogger(__name__)

logger.debug(f"Loading connection module (PID: {os.getpid()})")

DB_TYPE = os.getenv('DB_TYPE', 'sqlite')

# Allow overriding DB name for testing
DB_NAME = os.getenv('TEST_DB_NAME') or os.path.join(DATA_DIR, "threat_feed.db")

# Global Lock for SQLite DB Writes (Postgres handles concurrency itself)
# CRITICAL: Use RLock to allow nested transactions from the same thread
DB_WRITE_LOCK = threading.RLock()

# Postgres Connection Pool
pg_pool = None
pg_pool_lock = threading.Lock()

def init_pg_pool():
    global pg_pool
    if DB_TYPE == 'postgres' and not pg_pool:
        with pg_pool_lock:
            if not pg_pool: # Double check inside lock
                try:
                    pg_pool = psycopg2.pool.ThreadedConnectionPool(
                        minconn=1,
                        maxconn=20,
                        user=os.getenv('DB_USER', 'threat_user'),
                        password=os.getenv('DB_PASS', ''),
                        host=os.getenv('DB_HOST', 'postgres'),
                        port=os.getenv('DB_PORT', '5432'),
                        database=os.getenv('DB_NAME', 'threat_feed')
                    )
                    logger.info("PostgreSQL connection pool initialized.")
                except Exception as e:
                    logger.error(f"Failed to initialize Postgres pool: {e}")
                    raise

class PostgresCursorWrapper:
    """
    Wraps psycopg2 cursor to mimic sqlite3 behavior:
    1. Replaces '?' placeholders with '%s'.
    2. Allows accessing rows like dictionaries (already done by DictCursor).
    3. Handles 'INSERT OR IGNORE' -> 'ON CONFLICT DO NOTHING' conversion rudimentarily.
    """
    def __init__(self, cursor):
        self.cursor = cursor
        self.lastrowid = None # Postgres uses RETURNING id, handled via fetchone if needed

    def execute(self, query, params=None):
        # 1. Convert Placeholder '?' -> '%s'
        query_pg = query.replace('?', '%s')

        # 2. Convert 'INSERT OR IGNORE' -> 'INSERT ... ON CONFLICT DO NOTHING'
        if 'INSERT OR IGNORE' in query_pg:
            query_pg = query_pg.replace('INSERT OR IGNORE', 'INSERT')
            if 'ON CONFLICT' not in query_pg.upper():
                query_pg += " ON CONFLICT DO NOTHING"

        # 3. For INSERT statements without RETURNING, append RETURNING id to populate lastrowid
        is_insert = query_pg.strip().upper().startswith('INSERT')
        needs_returning = is_insert and 'RETURNING' not in query_pg.upper()
        if needs_returning:
            query_pg += " RETURNING id"

        # 4. Execute query
        try:
            self.cursor.execute(query_pg, params)
        except Exception as e:
            logger.error(f"SQL Error: {e} | Query: {query_pg}")
            raise

        # 5. Populate lastrowid from RETURNING clause
        if needs_returning:
            try:
                row = self.cursor.fetchone()
                self.lastrowid = row[0] if row else None
            except Exception:
                self.lastrowid = None

        return self

    def executemany(self, query, params_seq):
        query_pg = query.replace('?', '%s')
        self.cursor.executemany(query_pg, params_seq)
        return self

    def fetchone(self):
        return self.cursor.fetchone()

    def fetchall(self):
        return self.cursor.fetchall()

    def __iter__(self):
        """Allows iteration over the cursor (like sqlite3 cursor)."""
        return iter(self.cursor)

    @property
    def rowcount(self):
        return self.cursor.rowcount

    @property
    def description(self):
        return self.cursor.description

class PostgresConnectionWrapper:
    def __init__(self, conn, pool_obj):
        self.conn = conn
        self.pool = pool_obj
        self.row_factory = None # Compat attribute

    def execute(self, query, params=None):
        cursor = self.cursor()
        cursor.execute(query, params)
        return cursor

    def executemany(self, query, params_seq):
        cursor = self.cursor()
        cursor.executemany(query, params_seq)
        return cursor

    def cursor(self):
        return PostgresCursorWrapper(self.conn.cursor(cursor_factory=DictCursor))

    def commit(self):
        self.conn.commit()

    def rollback(self):
        self.conn.rollback()

    def close(self):
        if self.pool:
            self.pool.putconn(self.conn)

def get_db_connection(timeout=DB_TIMEOUT):
    if DB_TYPE == 'postgres':
        if not pg_pool:
            init_pg_pool()
        conn = pg_pool.getconn()
        return PostgresConnectionWrapper(conn, pg_pool)
    else:
        # SQLite Fallback
        conn = sqlite3.connect(DB_NAME, timeout=timeout)
        conn.execute('PRAGMA journal_mode=WAL;')
        conn.execute('PRAGMA foreign_keys=ON;')
        conn.row_factory = sqlite3.Row
        return conn

@contextmanager
def db_transaction(conn=None):
    """
    Context manager for database transactions.
    Ensures that for SQLite, we use a global RLock to prevent "database is locked".
    """
    should_close = False
    if conn is None:
        conn = get_db_connection()
        should_close = True

    try:
        if DB_TYPE == 'sqlite':
            with DB_WRITE_LOCK:
                yield conn
                if should_close:
                    conn.commit()
        else:
            yield conn
            if should_close:
                conn.commit()
    except Exception as e:
        if should_close:
            try:
                conn.rollback()
            except Exception:
                pass
        raise e
    finally:
        if should_close:
            conn.close()


@contextmanager
def db_readonly():
    """
    Context manager for read-only database queries.
    Does NOT acquire the write lock — allows concurrent reads in SQLite WAL mode.
    """
    conn = get_db_connection()
    try:
        yield conn
    finally:
        conn.close()
