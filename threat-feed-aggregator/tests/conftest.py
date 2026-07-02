import os
import sys
import tempfile

# Skip scheduler initialization during tests (must be set before app import)
os.environ["GUNICORN_WORKER"] = "1"
os.environ.setdefault("DB_TYPE", "sqlite")

# ---------------------------------------------------------------------------
# Mock optional / unavailable packages before the app is imported.
# This allows the test suite to run in environments where not every system
# dependency (ldap, geoip, crypto, image libs…) is installed.
# ---------------------------------------------------------------------------
from unittest.mock import MagicMock


def _mock_module(name, **attrs):
    """Register a MagicMock for *name* (and any dotted sub-paths) in sys.modules."""
    m = MagicMock(**attrs)
    sys.modules[name] = m
    return m


def _try_import(name):
    """Return True if *name* can be imported without error."""
    try:
        __import__(name)
        return True
    except (ImportError, SyntaxError):
        return False


# -- aiohttp: 0.x uses asyncio.async() which is a SyntaxError in Python 3.7+
if not _try_import("aiohttp"):
    _ah = _mock_module("aiohttp")
    _ah.BasicAuth = MagicMock
    _ah.ClientSession = MagicMock
    _ah.ClientTimeout = MagicMock
    _ah.TCPConnector = MagicMock
    _ah.ClientError = Exception
    _ah.ServerDisconnectedError = Exception
    _ah.ClientResponseError = Exception
    _ah.ClientConnectorError = Exception

# -- geoip2: optional geo-IP enrichment library
if not _try_import("geoip2"):
    _gi = _mock_module("geoip2")
    _gi_db = _mock_module("geoip2.database")
    _gi_err = _mock_module("geoip2.errors")
    _gi_err.AddressNotFoundError = Exception
    _gi.database = _gi_db
    _gi.errors = _gi_err

# -- pyotp: TOTP / MFA library
if not _try_import("pyotp"):
    _pyotp = _mock_module("pyotp")
    _pyotp.random_base32 = lambda: "JBSWY3DPEHPK3PXP"
    _pyotp.TOTP = MagicMock
    _pyotp.totp = MagicMock()
    _pyotp.totp.TOTP = MagicMock

# -- qrcode: QR code image generation
if not _try_import("qrcode"):
    _qr = _mock_module("qrcode")
    _qr.QRCode = MagicMock

# -- Pillow (PIL): image library used by qrcode
if not _try_import("PIL"):
    _pil = _mock_module("PIL")
    _mock_module("PIL.Image")

# -- ldap3: LDAP authentication
if not _try_import("ldap3"):
    _ldap = _mock_module("ldap3")
    _ldap.ALL = "ALL"
    _ldap.Connection = MagicMock
    _ldap.Server = MagicMock
    _ldap.Tls = MagicMock
    _mock_module("ldap3.utils")
    _ldap3_dn = _mock_module("ldap3.utils.dn")
    _ldap3_dn.escape_rdn = lambda s: s
    _ldap3_conv = _mock_module("ldap3.utils.conv")
    _ldap3_conv.escape_filter_chars = lambda s: s

# -- PyJWT / jwt: JWT token handling (ITAI SSO)
if not _try_import("jwt"):
    _jwt = _mock_module("jwt")
    _jwt.decode = MagicMock(return_value={})
    _jwt.encode = MagicMock(return_value="mock.token.here")
    _jwt.ExpiredSignatureError = Exception
    _jwt.InvalidTokenError = Exception
    _jwt.DecodeError = Exception

# -- cryptography: required by some JWT / TLS paths
if not _try_import("cryptography"):
    _crypto = _mock_module("cryptography")
    _mock_module("cryptography.hazmat")
    _mock_module("cryptography.hazmat.primitives")
    _mock_module("cryptography.hazmat.primitives.hashes")
    _mock_module("cryptography.hazmat.primitives.serialization")
    _mock_module("cryptography.hazmat.primitives.serialization.pkcs12")
    _mock_module("cryptography.hazmat.primitives.asymmetric")
    _mock_module("cryptography.hazmat.primitives.asymmetric.rsa")
    _mock_module("cryptography.hazmat.backends")
    _mock_module("cryptography.x509")
    _mock_module("cryptography.x509.oid")

# -- psycopg2: PostgreSQL driver (tests always use SQLite)
if not _try_import("psycopg2"):
    _pg = _mock_module("psycopg2")
    _pg.connect = MagicMock
    _pg.IntegrityError = Exception
    _pg.OperationalError = Exception
    _mock_module("psycopg2.extras")
    _mock_module("psycopg2.pool")

# -- apscheduler: background job scheduler (scheduler_manager is already mocked,
#    but apscheduler itself may be imported directly in some modules)
if not _try_import("apscheduler"):
    _aps = _mock_module("apscheduler")
    _mock_module("apscheduler.schedulers")
    _aps_bg = _mock_module("apscheduler.schedulers.background")
    _aps_bg.BackgroundScheduler = MagicMock
    _mock_module("apscheduler.jobstores")
    _mock_module("apscheduler.jobstores.sqlalchemy")
    _mock_module("apscheduler.triggers")
    _mock_module("apscheduler.triggers.interval")
    _aps_int = _mock_module("apscheduler.triggers.interval")
    _aps_int.IntervalTrigger = MagicMock

# -- pydantic: config schema validation
if not _try_import("pydantic"):
    _pyd = _mock_module("pydantic")
    _pyd.BaseModel = MagicMock
    _pyd.field_validator = lambda *a, **kw: (lambda f: f)
    _pyd.ValidationError = Exception

# -- aiodns: async DNS resolver used by dns_deduplication
if not _try_import("aiodns"):
    _mock_module("aiodns")

# -- defusedxml: safe XML parsing for import endpoints
if not _try_import("defusedxml"):
    _dfx = _mock_module("defusedxml")
    _mock_module("defusedxml.ElementTree")

# -- whois: WHOIS lookup for investigation service
if not _try_import("whois"):
    _mock_module("whois")

# -- dnspython (dns): DNS resolution used by system routes
if not _try_import("dns"):
    _dns = _mock_module("dns")
    _mock_module("dns.resolver")
    _mock_module("dns.exception")

# -- prometheus_client: metrics endpoint (optional, not installed in test env)
if not _try_import("prometheus_client"):
    _prom = _mock_module("prometheus_client")
    _prom.CONTENT_TYPE_LATEST = "text/plain"
    _prom.CollectorRegistry = MagicMock
    _prom.Gauge = MagicMock
    _prom.generate_latest = MagicMock(return_value=b"")

_mock_scheduler = MagicMock()
_mock_scheduler.running = False
_mock_scheduler.get_jobs.return_value = []

_mock_sched_module = MagicMock(
    scheduler=_mock_scheduler,
    update_scheduled_jobs=MagicMock(),
    init_scheduler=MagicMock(),
)
sys.modules["threat_feed_aggregator.scheduler_manager"] = _mock_sched_module

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
def lists_client(client):
    """system:r (sistem yetkisi yok) ama lists:rw olan kullanıcı.
    list_management_required decorator'ını system:rw olmadan test etmek için."""
    with client.session_transaction() as sess:
        sess["logged_in"] = True
        sess["username"] = "listmanager"
        sess["permissions"] = {
            "dashboard": "rw",
            "system": "r",
            "tools": "r",
            "lists": "rw",
        }
        sess["profile_name"] = "List_Manager"
    return client


@pytest.fixture()
def runner(app):
    return app.test_cli_runner()
