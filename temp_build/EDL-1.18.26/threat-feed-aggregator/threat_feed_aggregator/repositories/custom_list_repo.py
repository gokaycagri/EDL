import json
import logging
import secrets
from datetime import datetime, UTC
from ..database.connection import db_transaction, DB_WRITE_LOCK

logger = logging.getLogger(__name__)

def create_custom_list(name, sources, types, data_format, conn=None):
    """
    Creates a new custom EDL configuration.
    sources: list of source names
    types: list of types (ip, domain, url)
    """
    token = secrets.token_urlsafe(16)
    created_at = datetime.now(UTC).isoformat()
    
    # Store lists as JSON strings
    sources_json = json.dumps(sources)
    types_json = json.dumps(types)
    
    logger.info(f"Creating custom list '{name}' with sources: {sources}")

    with DB_WRITE_LOCK:
        with db_transaction(conn) as db:
            cursor = db.execute('''
                INSERT INTO custom_lists (name, token, sources, types, format, created_at)
                VALUES (?, ?, ?, ?, ?, ?)
            ''', (name, token, sources_json, types_json, data_format, created_at))
            db.commit()
            logger.info(f"Custom list '{name}' created with ID: {cursor.lastrowid}")
            return cursor.lastrowid, token

def get_all_custom_lists(conn=None):
    with db_transaction(conn) as db:
        cursor = db.execute('SELECT * FROM custom_lists ORDER BY created_at DESC')
        results = []
        for row in cursor:
            # Optimization: Don't calculate counts here. Fetch via AJAX.
            results.append({
                'id': row['id'],
                'name': row['name'],
                'token': row['token'],
                'sources': json.loads(row['sources']),
                'types': json.loads(row['types']),
                'format': row['format'],
                'created_at': row['created_at'],
                'indicator_count': None 
            })
        logger.info(f"Retrieved {len(results)} custom lists.")
        return results

def get_custom_list_by_token(token, conn=None):
    with db_transaction(conn) as db:
        cursor = db.execute('SELECT * FROM custom_lists WHERE token = ?', (token,))
        row = cursor.fetchone()
        if row:
            return {
                'id': row['id'],
                'name': row['name'],
                'token': row['token'],
                'sources': json.loads(row['sources']),
                'types': json.loads(row['types']),
                'format': row['format'],
                'created_at': row['created_at']
            }
        return None

def delete_custom_list(list_id, conn=None):
    with DB_WRITE_LOCK:
        with db_transaction(conn) as db:
            try:
                db.execute('DELETE FROM custom_lists WHERE id = ?', (list_id,))
                db.commit()
                return True
            except Exception as e:
                logger.error(f"Error deleting custom list {list_id}: {e}")
                return False

def get_custom_list_count(list_id, conn=None):
    """
    Calculates the indicator count for a specific custom list.
    """
    with db_transaction(conn) as db:
        cursor = db.execute('SELECT sources FROM custom_lists WHERE id = ?', (list_id,))
        row = cursor.fetchone()
        if not row: return 0
        
        sources = json.loads(row['sources'])
        if not sources: return 0
        
        if len(sources) == 1:
            count_cursor = db.execute(
                'SELECT COUNT(*) FROM indicator_sources WHERE source_name = ?', 
                (sources[0],)
            )
        else:
            placeholders = ','.join(['?'] * len(sources))
            count_cursor = db.execute(f'''
                SELECT COUNT(DISTINCT indicator)
                FROM indicator_sources
                WHERE source_name IN ({placeholders})
            ''', sources)
            
        return count_cursor.fetchone()[0]
