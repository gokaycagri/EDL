"""
Audit logging service — records security-relevant actions for compliance and forensics.
"""
import logging
from datetime import UTC, datetime

from ..database.connection import db_transaction

logger = logging.getLogger(__name__)


def log_action(username, action, target=None, details=None, ip_address=None):
    """
    Record an audit event.

    Args:
        username: Who performed the action
        action: Action type (e.g. 'login', 'user_create', 'source_add', 'config_change', 'backup_download')
        target: What was acted upon (e.g. source name, username)
        details: Additional context
        ip_address: Client IP
    """
    try:
        with db_transaction() as db:
            db.execute(
                """INSERT INTO audit_log (timestamp, username, action, target, details, ip_address)
                   VALUES (?, ?, ?, ?, ?, ?)""",
                (datetime.now(UTC).isoformat(), username, action, target, details, ip_address),
            )
    except Exception as e:
        # Audit logging must never crash the application
        logger.error(f"Audit log write failed: {e}")


def get_audit_log(limit=100, offset=0, username=None, action=None):
    """Retrieve audit log entries with optional filtering."""
    with db_transaction() as db:
        query = "SELECT * FROM audit_log"
        params = []
        conditions = []

        if username:
            conditions.append("username = ?")
            params.append(username)
        if action:
            conditions.append("action = ?")
            params.append(action)

        if conditions:
            query += " WHERE " + " AND ".join(conditions)
        query += " ORDER BY timestamp DESC LIMIT ? OFFSET ?"
        params.extend([limit, offset])

        cursor = db.execute(query, params)
        return [dict(row) for row in cursor.fetchall()]
