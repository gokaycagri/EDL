import logging
from datetime import UTC, datetime

from ..database.connection import DB_WRITE_LOCK, db_transaction

logger = logging.getLogger(__name__)

# ... (Job History functions) ...
def log_job_start(source_name, conn=None):
    with DB_WRITE_LOCK:
        with db_transaction(conn) as db:
            try:
                start_time = datetime.now(UTC).isoformat()
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
                end_time = datetime.now(UTC).isoformat()
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

def get_latest_job_times(conn=None):
    """
    Returns a dictionary mapping source_name to the latest successful end_time.
    """
    with db_transaction(conn) as db:
        try:
            cursor = db.execute('''
                SELECT source_name, MAX(end_time) as last_updated
                FROM job_history
                WHERE status = 'success' AND end_time IS NOT NULL
                GROUP BY source_name
            ''')
            return {row['source_name']: row['last_updated'] for row in cursor.fetchall()}
        except Exception as e:
            logger.error(f"Error getting latest job times: {e}")
            return {}
