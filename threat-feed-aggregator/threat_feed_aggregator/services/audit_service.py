"""
Audit logging service — records security-relevant actions for compliance and forensics.
"""

from datetime import UTC, datetime
import logging

from ..database.connection import db_readonly, db_transaction

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


def _build_audit_conditions(username=None, action=None, date_from=None, date_to=None, target=None, ip_address=None):
    conditions, params = [], []
    if username:
        conditions.append("username = ?")
        params.append(username)
    if action:
        conditions.append("action = ?")
        params.append(action)
    if date_from:
        conditions.append("timestamp >= ?")
        params.append(date_from)
    if date_to:
        conditions.append("timestamp <= ?")
        params.append(date_to + "T23:59:59" if len(date_to) == 10 else date_to)
    if target:
        conditions.append("target LIKE ?")
        params.append(f"%{target}%")
    if ip_address:
        conditions.append("ip_address LIKE ?")
        params.append(f"%{ip_address}%")
    return conditions, params


def get_audit_log(limit=100, offset=0, username=None, action=None, date_from=None, date_to=None, target=None, ip_address=None):
    """Retrieve audit log entries with optional filtering."""
    with db_readonly() as db:
        conditions, params = _build_audit_conditions(username, action, date_from, date_to, target, ip_address)
        query = "SELECT * FROM audit_log"
        if conditions:
            query += " WHERE " + " AND ".join(conditions)
        query += " ORDER BY timestamp DESC LIMIT ? OFFSET ?"
        params.extend([limit, offset])
        cursor = db.execute(query, params)
        return [dict(row) for row in cursor.fetchall()]


def get_audit_log_count(username=None, action=None, date_from=None, date_to=None, target=None, ip_address=None) -> int:
    """Return total count of matching audit log entries (for pagination)."""
    with db_readonly() as db:
        conditions, params = _build_audit_conditions(username, action, date_from, date_to, target, ip_address)
        query = "SELECT COUNT(*) FROM audit_log"
        if conditions:
            query += " WHERE " + " AND ".join(conditions)
        row = db.execute(query, params).fetchone()
        return row[0] if row else 0
