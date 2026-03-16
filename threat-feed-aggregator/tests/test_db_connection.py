"""Tests for database connection and transaction management."""
import os
import sqlite3
import importlib
import pytest


@pytest.fixture()
def db_path(tmp_path):
    """Create a test SQLite database with fresh module reload."""
    path = str(tmp_path / "test.db")
    os.environ["TEST_DB_NAME"] = path
    os.environ["DB_TYPE"] = "sqlite"

    # Reload connection module to pick up new TEST_DB_NAME
    import threat_feed_aggregator.database.connection as conn_mod
    importlib.reload(conn_mod)

    conn = conn_mod.get_db_connection()
    conn.execute("CREATE TABLE IF NOT EXISTS test_items (id INTEGER PRIMARY KEY, name TEXT)")
    conn.commit()
    conn.close()

    yield path
    os.environ.pop("TEST_DB_NAME", None)


class TestDbTransaction:
    def test_auto_commit_on_success(self, db_path):
        import threat_feed_aggregator.database.connection as conn_mod
        importlib.reload(conn_mod)

        with conn_mod.db_transaction() as db:
            db.execute("INSERT INTO test_items (name) VALUES (?)", ("item1",))

        conn = conn_mod.get_db_connection()
        result = conn.execute("SELECT name FROM test_items").fetchone()
        conn.close()
        assert result[0] == "item1"

    def test_auto_rollback_on_exception(self, db_path):
        import threat_feed_aggregator.database.connection as conn_mod
        importlib.reload(conn_mod)

        with pytest.raises(ValueError):
            with conn_mod.db_transaction() as db:
                db.execute("INSERT INTO test_items (name) VALUES (?)", ("item2",))
                raise ValueError("test error")

        conn = conn_mod.get_db_connection()
        result = conn.execute("SELECT COUNT(*) FROM test_items").fetchone()
        conn.close()
        assert result[0] == 0


class TestDbReadonly:
    def test_readonly_returns_data(self, db_path):
        import threat_feed_aggregator.database.connection as conn_mod
        importlib.reload(conn_mod)

        conn = conn_mod.get_db_connection()
        conn.execute("INSERT INTO test_items (name) VALUES (?)", ("readonly_test",))
        conn.commit()
        conn.close()

        with conn_mod.db_readonly() as db:
            result = db.execute("SELECT name FROM test_items").fetchone()
            assert result[0] == "readonly_test"


class TestGetDbConnection:
    def test_sqlite_wal_mode(self, db_path):
        import threat_feed_aggregator.database.connection as conn_mod
        importlib.reload(conn_mod)

        conn = conn_mod.get_db_connection()
        result = conn.execute("PRAGMA journal_mode").fetchone()
        conn.close()
        assert result[0] == "wal"

    def test_sqlite_foreign_keys_enabled(self, db_path):
        import threat_feed_aggregator.database.connection as conn_mod
        importlib.reload(conn_mod)

        conn = conn_mod.get_db_connection()
        result = conn.execute("PRAGMA foreign_keys").fetchone()
        conn.close()
        assert result[0] == 1
