from datetime import UTC, datetime
import logging
import sqlite3

try:
    from psycopg2 import IntegrityError as PgIntegrityError
except ImportError:
    PgIntegrityError = type(None)

from ..database.connection import db_transaction

logger = logging.getLogger(__name__)


# --- Whitelist Functions ---
def add_whitelist_item(item, item_type="ip", description="", conn=None):
    if not item:
        return False, "Item is empty."

    from ..utils import validate_indicator

    is_valid, inferred_type = validate_indicator(item)
    if not is_valid:
        return False, f"'{item}' is not a valid IP, CIDR, or Domain/URL."

    if inferred_type != "unknown":
        item_type = inferred_type

    with db_transaction(conn) as db:
        try:
            now_iso = datetime.now(UTC).isoformat()
            db.execute(
                "INSERT INTO whitelist (item, type, description, added_at) VALUES (?, ?, ?, ?)",
                (item.strip(), item_type, description, now_iso),
            )
            return True, "Item added to whitelist."
        except (sqlite3.IntegrityError, PgIntegrityError):
            return False, "Item already in whitelist."
        except Exception as e:
            logger.error(f"Error adding to whitelist: {e}")
            return False, str(e)


def get_whitelist(conn=None, limit=None):
    with db_transaction(conn) as db:
        if limit is not None:
            cursor = db.execute("SELECT * FROM whitelist ORDER BY added_at DESC LIMIT ?", (limit,))
        else:
            cursor = db.execute("SELECT * FROM whitelist ORDER BY added_at DESC")
        return [dict(row) for row in cursor.fetchall()]


def remove_whitelist_item(item_id, conn=None):
    with db_transaction(conn) as db:
        try:
            db.execute("DELETE FROM whitelist WHERE id = ?", (item_id,))
            return True
        except Exception as e:
            logger.error(f"Error removing from whitelist: {e}")
            return False


def update_whitelist_item(item_id, new_item, item_type="ip", description="", conn=None):
    """Updates an existing whitelist item."""
    if not new_item:
        return False, "Item cannot be empty."

    from ..utils import validate_indicator

    is_valid, inferred_type = validate_indicator(new_item)
    if not is_valid:
        return False, f"'{new_item}' is not a valid IP, CIDR, or Domain/URL."

    if inferred_type != "unknown":
        item_type = inferred_type

    with db_transaction(conn) as db:
        try:
            db.execute(
                "UPDATE whitelist SET item = ?, type = ?, description = ? WHERE id = ?",
                (new_item.strip(), item_type, description, item_id),
            )
            return True, "Item updated successfully."
        except (sqlite3.IntegrityError, PgIntegrityError):
            return False, "Item already exists in whitelist."
        except Exception as e:
            logger.error(f"Error updating whitelist item: {e}")
            return False, str(e)


# --- API Blacklist Functions ---
def add_api_blacklist_item(item, item_type="ip", comment="", expires_at=None, conn=None, source=None):
    if not item:
        return False, "Item is empty."

    if source:
        comment = f"[{source}] {comment}".strip()

    from ..utils import is_rfc1918_private_ipv4_indicator, validate_indicator

    is_valid, _ = validate_indicator(item)
    if not is_valid:
        return False, f"'{item}' is not a valid IP, CIDR, or Domain/URL."

    if is_rfc1918_private_ipv4_indicator(item, item_type):
        return False, "RFC1918 private IPv4 indicators cannot be added to blacklist."

    # We use db_transaction to ensure proper locking and transaction management
    with db_transaction(conn) as db:
        try:
            now_iso = datetime.now(UTC).isoformat()

            from ..database.connection import DB_TYPE

            # Manual adds (no source) should reject duplicates; feed-based adds upsert silently.
            if source is None:
                existing = db.execute(
                    "SELECT 1 FROM api_blacklist WHERE item = ?", (item.strip(),)
                ).fetchone()
                if existing:
                    return False, "Item already exists in block list."

            if DB_TYPE == "postgres":
                # Optimized UPSERT for Postgres
                query = """
                    INSERT INTO api_blacklist (item, type, comment, added_at, expires_at)
                    VALUES (%s, %s, %s, %s, %s)
                    ON CONFLICT (item)
                    DO UPDATE SET
                        comment = EXCLUDED.comment,
                        added_at = EXCLUDED.added_at,
                        expires_at = EXCLUDED.expires_at
                """
                db.execute(query, (item.strip(), item_type, comment, now_iso, expires_at))
                return True, "Item added or refreshed in blacklist."
            else:
                # SQLite: use INSERT OR REPLACE for atomic upsert
                db.execute(
                    """INSERT OR REPLACE INTO api_blacklist (item, type, comment, added_at, expires_at)
                              VALUES (?, ?, ?, ?, ?)""",
                    (item.strip(), item_type, comment, now_iso, expires_at),
                )
                return True, "Item added or refreshed in blacklist."
        except Exception as e:
            logger.error(f"Error adding to api_blacklist: {e}")
            return False, str(e)


def get_expired_blacklist_items(conn=None):
    """Returns items whose expires_at has passed, without deleting them (preview/dry-run)."""
    from ..database.connection import db_readonly

    with db_readonly() as db:
        try:
            now_iso = datetime.now(UTC).isoformat()
            cursor = db.execute(
                "SELECT item, type, comment, added_at, expires_at FROM api_blacklist"
                " WHERE expires_at IS NOT NULL AND expires_at < ? ORDER BY expires_at ASC",
                (now_iso,),
            )
            return [dict(row) for row in cursor.fetchall()]
        except Exception as e:
            logger.error(f"Error fetching expired blacklist items: {e}")
            return []


def remove_expired_blacklist_items(conn=None):
    """
    Removes items from API blacklist that have passed their expiration date.

    Returns:
        (deleted_count, deleted_items) — count of removed rows and their details,
        so callers can write audit log entries or regenerate EDL files as needed.
    """
    with db_transaction(conn) as db:
        try:
            now_iso = datetime.now(UTC).isoformat()
            # Fetch details first (same transaction) so callers can audit what was removed
            cursor = db.execute(
                "SELECT item, type, comment, added_at, expires_at FROM api_blacklist"
                " WHERE expires_at IS NOT NULL AND expires_at < ?",
                (now_iso,),
            )
            expired_items = [dict(row) for row in cursor.fetchall()]
            if not expired_items:
                return 0, []
            cursor = db.execute(
                "DELETE FROM api_blacklist WHERE expires_at IS NOT NULL AND expires_at < ?", (now_iso,)
            )
            deleted = cursor.rowcount
            if deleted > 0:
                logger.info("Cleanup: Removed %d expired blacklist item(s).", deleted)
            return deleted, expired_items
        except Exception as e:
            logger.error(f"Error removing expired blacklist items: {e}")
            return 0, []


def get_api_blacklist_items(conn=None, limit=None):
    with db_transaction(conn) as db:
        if limit is not None:
            cursor = db.execute("SELECT * FROM api_blacklist ORDER BY added_at DESC LIMIT ?", (limit,))
        else:
            cursor = db.execute("SELECT * FROM api_blacklist ORDER BY added_at DESC")
        return [dict(row) for row in cursor.fetchall()]


def get_api_blacklist_item_by_value(item, conn=None):
    """Retrieves a specific blacklist item by its value."""
    with db_transaction(conn) as db:
        row = db.execute("SELECT * FROM api_blacklist WHERE item = ?", (item.strip(),)).fetchone()
        return dict(row) if row else None


def remove_api_blacklist_item(item, conn=None):
    with db_transaction(conn) as db:
        try:
            # Can remove by ID or exact item string
            if isinstance(item, int) or (isinstance(item, str) and item.isdigit()):
                db.execute("DELETE FROM api_blacklist WHERE id = ?", (item,))
            else:
                db.execute("DELETE FROM api_blacklist WHERE item = ?", (item,))
            return True
        except Exception as e:
            logger.error(f"Error removing from api_blacklist: {e}")
            return False


def update_api_blacklist_item(item_id, new_item, item_type="ip", comment="", conn=None):
    """Updates an existing blacklist item."""
    if not new_item:
        return False, "Item cannot be empty."

    from ..utils import is_rfc1918_private_ipv4_indicator, validate_indicator

    is_valid, inferred_type = validate_indicator(new_item)
    if not is_valid:
        return False, f"'{new_item}' is not a valid IP, CIDR, or Domain/URL."

    if inferred_type != "unknown":
        item_type = inferred_type

    if is_rfc1918_private_ipv4_indicator(new_item, item_type):
        return False, "RFC1918 private IPv4 indicators cannot be added to blacklist."

    with db_transaction(conn) as db:
        try:
            db.execute(
                "UPDATE api_blacklist SET item = ?, type = ?, comment = ? WHERE id = ?",
                (new_item.strip(), item_type, comment, item_id),
            )
            return True, "Item updated successfully."
        except sqlite3.IntegrityError:
            return False, "Item already exists in blacklist."
        except Exception as e:
            logger.error(f"Error updating api_blacklist item: {e}")
            return False, str(e)


def delete_whitelisted_indicators(items_to_delete, conn=None):
    with db_transaction(conn) as db:
        try:
            if items_to_delete:
                placeholders = ",".join(["?" for _ in items_to_delete])
                db.execute(f"DELETE FROM indicators WHERE indicator IN ({placeholders})", items_to_delete)
                db.execute(f"DELETE FROM indicator_sources WHERE indicator IN ({placeholders})", items_to_delete)
                return True
            return False
        except Exception as e:
            logger.error(f"Error deleting whitelisted indicators: {e}")
            return False
