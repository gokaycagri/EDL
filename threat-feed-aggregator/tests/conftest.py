import os
import sys
import tempfile

import pytest

# Compatibility Shim
try:
    import werkzeug
    if not hasattr(werkzeug, 'exceptions'):
        import werkzeug.exceptions
        sys.modules['werkzeug.exceptions'] = werkzeug.exceptions
except ImportError:
    pass


@pytest.fixture(autouse=True)
def _isolate_db(tmp_path):
    """Automatically isolate every test with a temp SQLite database."""
    db_path = str(tmp_path / "test_threat_feed.db")
    os.environ["TEST_DB_NAME"] = db_path
    os.environ["DB_TYPE"] = "sqlite"
    yield
    os.environ.pop("TEST_DB_NAME", None)


@pytest.fixture()
def app(_isolate_db):
    """Flask app configured for testing with isolated DB."""
    from threat_feed_aggregator.app import app as flask_app
    from threat_feed_aggregator.database.schema import init_db

    flask_app.config.update({
        "TESTING": True,
        "WTF_CSRF_ENABLED": False,
        "SESSION_TYPE": "filesystem",
        "SESSION_FILE_DIR": tempfile.mkdtemp(),
        "SECRET_KEY": "test_secret_key_for_testing",
    })

    with flask_app.app_context():
        init_db()

    yield flask_app


@pytest.fixture()
def client(app):
    """Unauthenticated Flask test client."""
    return app.test_client()


@pytest.fixture()
def auth_client(client):
    """Test client with pre-authenticated admin session (Super_User)."""
    with client.session_transaction() as sess:
        sess["logged_in"] = True
        sess["username"] = "admin"
        sess["permissions"] = {
            "dashboard": "rw",
            "system": "rw",
            "tools": "rw",
            "analysis": "rw",
        }
        sess["profile_name"] = "Super_User"
    return client


@pytest.fixture()
def readonly_client(client):
    """Test client with read-only permissions."""
    with client.session_transaction() as sess:
        sess["logged_in"] = True
        sess["username"] = "viewer"
        sess["permissions"] = {
            "dashboard": "r",
            "system": "r",
            "tools": "r",
            "analysis": "r",
        }
        sess["profile_name"] = "Read_Only"
    return client


@pytest.fixture()
def runner(app):
    return app.test_cli_runner()
