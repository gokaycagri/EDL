"""Tests for audit logging service."""
import importlib
import os
import pytest


@pytest.fixture()
def db_with_audit(tmp_path):
    """Create test DB with audit_log table."""
    db_path = str(tmp_path / "test_audit.db")
    os.environ["TEST_DB_NAME"] = db_path
    os.environ["DB_TYPE"] = "sqlite"

    import threat_feed_aggregator.database.connection as conn_mod
    importlib.reload(conn_mod)

    conn = conn_mod.get_db_connection()
    from threat_feed_aggregator.database.schema import init_db
    init_db(conn)
    conn.commit()
    conn.close()
    yield db_path
    os.environ.pop("TEST_DB_NAME", None)


class TestLogAction:
    def test_writes_audit_entry(self, db_with_audit):
        from threat_feed_aggregator.services.audit_service import log_action, get_audit_log

        log_action("admin", "login", ip_address="127.0.0.1")

        entries = get_audit_log()
        assert len(entries) == 1
        assert entries[0]["username"] == "admin"
        assert entries[0]["action"] == "login"
        assert entries[0]["ip_address"] == "127.0.0.1"

    def test_multiple_entries(self, db_with_audit):
        from threat_feed_aggregator.services.audit_service import log_action, get_audit_log

        log_action("admin", "login")
        log_action("admin", "user_create", target="newuser")
        log_action("admin", "backup_download")

        entries = get_audit_log()
        assert len(entries) == 3

    def test_entry_with_details(self, db_with_audit):
        from threat_feed_aggregator.services.audit_service import log_action, get_audit_log

        log_action("admin", "config_change", target="proxy", details="enabled=true")

        entries = get_audit_log()
        assert entries[0]["details"] == "enabled=true"
        assert entries[0]["target"] == "proxy"


class TestGetAuditLog:
    def test_filter_by_username(self, db_with_audit):
        from threat_feed_aggregator.services.audit_service import log_action, get_audit_log

        log_action("admin", "login")
        log_action("viewer", "login")

        entries = get_audit_log(username="admin")
        assert len(entries) == 1
        assert entries[0]["username"] == "admin"

    def test_filter_by_action(self, db_with_audit):
        from threat_feed_aggregator.services.audit_service import log_action, get_audit_log

        log_action("admin", "login")
        log_action("admin", "backup_download")

        entries = get_audit_log(action="login")
        assert len(entries) == 1

    def test_limit_and_offset(self, db_with_audit):
        from threat_feed_aggregator.services.audit_service import log_action, get_audit_log

        for i in range(10):
            log_action("admin", f"action_{i}")

        entries = get_audit_log(limit=3)
        assert len(entries) == 3

        entries_offset = get_audit_log(limit=3, offset=3)
        assert len(entries_offset) == 3
        assert entries[0]["action"] != entries_offset[0]["action"]

    def test_ordered_by_timestamp_desc(self, db_with_audit):
        from threat_feed_aggregator.services.audit_service import log_action, get_audit_log

        log_action("admin", "first")
        log_action("admin", "second")

        entries = get_audit_log()
        assert entries[0]["action"] == "second"  # newest first
