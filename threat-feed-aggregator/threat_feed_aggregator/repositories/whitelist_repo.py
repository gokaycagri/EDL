import logging
import sqlite3
from datetime import UTC, datetime

from ..database.connection import DB_WRITE_LOCK, db_transaction, get_db_connection

logger = logging.getLogger(__name__)

# --- Whitelist Functions ---
def add_whitelist_item(item, item_type='ip', description="", conn=None):
    if not item:
        return False, "Item is empty."

    from ..utils import validate_indicator
    is_valid, inferred_type = validate_indicator(item)
    if not is_valid:
        return False, f"'{item}' is not a valid IP, CIDR, or Domain/URL."
    
    if inferred_type != 'unknown':
        item_type = inferred_type

    with DB_WRITE_LOCK:
        with db_transaction(conn) as db:
            try:
                now_iso = datetime.now(UTC).isoformat()
                db.execute('INSERT INTO whitelist (item, type, description, added_at) VALUES (?, ?, ?, ?)',
                             (item.strip(), item_type, description, now_iso))
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

def update_whitelist_item(item_id, new_item, item_type='ip', description="", conn=None):
    """Updates an existing whitelist item."""
    if not new_item:
        return False, "Item cannot be empty."

    from ..utils import validate_indicator
    is_valid, inferred_type = validate_indicator(new_item)
    if not is_valid:
        return False, f"'{new_item}' is not a valid IP, CIDR, or Domain/URL."
    
    if inferred_type != 'unknown':
        item_type = inferred_type

    with DB_WRITE_LOCK:
        with db_transaction(conn) as db:
            try:
                db.execute('UPDATE whitelist SET item = ?, type = ?, description = ? WHERE id = ?',
                           (new_item.strip(), item_type, description, item_id))
                db.commit()
                return True, "Item updated successfully."
            except sqlite3.IntegrityError:
                return False, "Item already exists in whitelist."
            except Exception as e:
                logger.error(f"Error updating whitelist item: {e}")
                return False, str(e)

# --- API Blacklist Functions ---
def add_api_blacklist_item(item, item_type='ip', comment="", expires_at=None, conn=None, source=None):
    if not item:
        return False, "Item is empty."

    if source:
        comment = f"[{source}] {comment}".strip()

    from ..utils import validate_indicator
    is_valid, _ = validate_indicator(item)
    if not is_valid:
        return False, f"'{item}' is not a valid IP, CIDR, or Domain/URL."

    with DB_WRITE_LOCK:
        # We handle transaction manually here to manage Postgres state correctly
        db = conn if conn else get_db_connection()
        try:
            now_iso = datetime.now(UTC).isoformat()
            
            from ..database.connection import DB_TYPE
            if DB_TYPE == 'postgres':
                # Optimized UPSERT for Postgres to avoid error logging in connection wrapper
                query = """
                    INSERT INTO api_blacklist (item, type, comment, added_at, expires_at) 
                    VALUES (?, ?, ?, ?, ?)
                    ON CONFLICT (item) 
                    DO UPDATE SET 
                        comment = EXCLUDED.comment,
                        added_at = EXCLUDED.added_at,
                        expires_at = EXCLUDED.expires_at
                """
                db.execute(query, (item.strip(), item_type, comment, now_iso, expires_at))
                db.commit()
                return True, "Item added or refreshed in blacklist."
            else:
                # SQLite fallback with try-except (SQLite doesn't log errors automatically in our wrapper)
                try:
                    db.execute('INSERT INTO api_blacklist (item, type, comment, added_at, expires_at) VALUES (?, ?, ?, ?, ?)',
                                 (item.strip(), item_type, comment, now_iso, expires_at))
                    db.commit()
                    return True, "Item added to blacklist."
                except Exception:
                    db.rollback()
                    db.execute('UPDATE api_blacklist SET comment = ?, added_at = ?, expires_at = ? WHERE item = ?',
                               (comment, now_iso, expires_at, item.strip()))
                    db.commit()
                    return True, "Item block refreshed."
        except Exception as e:
            logger.error(f"Error adding to api_blacklist: {e}")
            try: db.rollback()
            except: pass
            return False, str(e)
        finally:
            if not conn: db.close()

def remove_expired_blacklist_items(conn=None):
    """Removes items from API blacklist that have passed their expiration date."""
    with DB_WRITE_LOCK:
        with db_transaction(conn) as db:
            try:
                now_iso = datetime.now(UTC).isoformat()
                # expires_at is TEXT in ISO format, so we can compare lexicographically
                cursor = db.execute('DELETE FROM api_blacklist WHERE expires_at IS NOT NULL AND expires_at < ?', (now_iso,))
                deleted = cursor.rowcount
                if deleted > 0:
                    db.commit()
                    logger.info(f"Cleanup: Removed {deleted} expired blacklist items.")
                return deleted
            except Exception as e:
                logger.error(f"Error removing expired blacklist items: {e}")
                return 0

def get_api_blacklist_items(conn=None):
    with db_transaction(conn) as db:
        cursor = db.execute('SELECT * FROM api_blacklist ORDER BY added_at DESC')
        return [dict(row) for row in cursor.fetchall()]

def get_api_blacklist_item_by_value(item, conn=None):
    """Retrieves a specific blacklist item by its value."""
    with db_transaction(conn) as db:
        row = db.execute('SELECT * FROM api_blacklist WHERE item = ?', (item.strip(),)).fetchone()
        return dict(row) if row else None

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

def update_api_blacklist_item(item_id, new_item, item_type='ip', comment="", conn=None):
    """Updates an existing blacklist item."""
    if not new_item:
        return False, "Item cannot be empty."

    from ..utils import validate_indicator
    is_valid, inferred_type = validate_indicator(new_item)
    if not is_valid:
        return False, f"'{new_item}' is not a valid IP, CIDR, or Domain/URL."
    
    # Use inferred type if unknown or keep existing logic
    if inferred_type != 'unknown':
        item_type = inferred_type

    with DB_WRITE_LOCK:
        with db_transaction(conn) as db:
            try:
                db.execute('UPDATE api_blacklist SET item = ?, type = ?, comment = ? WHERE id = ?',
                           (new_item.strip(), item_type, comment, item_id))
                db.commit()
                return True, "Item updated successfully."
            except sqlite3.IntegrityError:
                return False, "Item already exists in blacklist."
            except Exception as e:
                logger.error(f"Error updating api_blacklist item: {e}")
                return False, str(e)

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
