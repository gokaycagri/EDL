import pytest
import sys
import os

# Compatibility Shim
try:
    import werkzeug
    if not hasattr(werkzeug, 'exceptions'):
        import werkzeug.exceptions
        sys.modules['werkzeug.exceptions'] = werkzeug.exceptions
except ImportError:
    pass

from threat_feed_aggregator.app import app as flask_app
from threat_feed_aggregator.database.schema import init_db

@pytest.fixture
def app():
    flask_app.config.update({
        "TESTING": True,
        "WTF_CSRF_ENABLED": False,
        "SESSION_TYPE": "filesystem",
        "SECRET_KEY": "test_key"
    })
    
    # Ensure fresh DB for each test if using sqlite memory, 
    # but here we follow project pattern
    with flask_app.app_context():
        init_db()
        
    yield flask_app

@pytest.fixture
def client(app):
    return app.test_client()

@pytest.fixture
def runner(app):
    return app.test_cli_runner()
