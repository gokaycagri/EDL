import json
import logging
import os
import sys

import redis

try:
    import werkzeug

    if not hasattr(werkzeug, "exceptions"):
        import werkzeug.exceptions

        sys.modules["werkzeug.exceptions"] = werkzeug.exceptions
except ImportError:
    pass

from .config_manager import DATA_DIR
from .database.schema import init_db
from .log_manager import setup_memory_logging
from .response_helpers import api_response
from .version import __version__

setup_memory_logging()
logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(name)s - %(message)s")
logger = logging.getLogger(__name__)

try:
    from flask_limiter import Limiter
    from flask_limiter.util import get_remote_address

    HAS_LIMITER = True
except ImportError:
    HAS_LIMITER = False
    logger.error("flask_limiter not found — rate limiting is DISABLED. Install flask-limiter for production.")

    # Dummy Limiter class to prevent AttributeError
    class Limiter:
        def __init__(self, *args, **kwargs):
            pass

        def init_app(self, app):
            pass

        def limit(self, *args, **kwargs):
            return lambda f: f

    def get_remote_address():
        return "127.0.0.1"


from flask import Flask  # noqa: I001
from flask_session import Session
from flask_wtf.csrf import CSRFProtect
from werkzeug.middleware.proxy_fix import ProxyFix

app = Flask(__name__)
# Trust proxy headers from 1 proxy level (OpenShift/Quay ingress)
# This ensures url_for(_external=True) generates correct HTTPS URLs
app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1, x_prefix=1)
csrf = CSRFProtect()
limiter = Limiter(get_remote_address, app=app, default_limits=[], storage_uri="memory://")


@app.template_filter("from_json")
def from_json_filter(value):
    try:
        return json.loads(value) if isinstance(value, str) else value
    except Exception:
        return value


_secret = os.environ.get("SECRET_KEY")
if not _secret:
    _secret = os.urandom(32).hex()
    logger.warning("SECRET_KEY not set — generated a random key. Sessions will not persist across restarts.")
app.config["SECRET_KEY"] = _secret
app.config["MAX_CONTENT_LENGTH"] = 100 * 1024 * 1024

if os.environ.get("REDIS_HOST"):
    app.config["SESSION_TYPE"] = "redis"
    redis_host = os.environ["REDIS_HOST"]
    redis_port = os.environ.get("REDIS_PORT", 6379)
    _redis_pass = os.environ.get("REDIS_PASSWORD", "")
    _redis_url = (
        f"redis://:{_redis_pass}@{redis_host}:{redis_port}"
        if _redis_pass
        else f"redis://{redis_host}:{redis_port}"
    )
    app.config["SESSION_REDIS"] = redis.from_url(_redis_url)
else:
    _session_dir = os.path.join(DATA_DIR, "flask_session")
    app.config["SESSION_TYPE"] = "filesystem"
    app.config["SESSION_FILE_DIR"] = _session_dir
    # Restrict session directory to owner-only (prevents other OS users reading sessions).
    try:
        os.makedirs(_session_dir, mode=0o700, exist_ok=True)
        os.chmod(_session_dir, 0o700)
    except OSError as _e:
        logger.warning("Could not restrict session directory permissions: %s", _e)

session_timeout = int(os.environ.get("SESSION_TIMEOUT_MINUTES", 60))
app.config["SESSION_PERMANENT"] = True
app.config["PERMANENT_SESSION_LIFETIME"] = session_timeout * 60
app.config["SESSION_USE_SIGNER"] = True
app.config["SESSION_REFRESH_EACH_REQUEST"] = True

# SESSION_COOKIE_SECURE: kullanıcı HTTPS üzerinden geliyorsa True olmalı.
# FORCE_HTTP_MODE=true → platform (OpenShift/ingress) TLS sonlandırıyor, pod HTTP çalışıyor
# ama son kullanıcı yine de HTTPS'te → Secure flag gerekli.
# FORCE_HTTPS=true → pod doğrudan TLS → yine Secure flag gerekli.
# Her iki durumda da cookie Secure olmalı; sadece tamamen HTTP ortamda False.
_force_http_mode = os.environ.get("FORCE_HTTP_MODE", "false").lower() in ("1", "true", "yes")
_force_https = os.environ.get("FORCE_HTTPS", "true").lower() in ("1", "true", "yes")
_is_https = _force_https or _force_http_mode
app.config["SESSION_COOKIE_SECURE"] = _is_https
app.config["SESSION_COOKIE_HTTPONLY"] = True
app.config["SESSION_COOKIE_SAMESITE"] = "Lax"

# CSRF token süre sınırını kaldır — token süresi dolunca "CSRF session token missing"
# hatası bazen login formunda ortaya çıkıyordu (varsayılan 3600s).
app.config["WTF_CSRF_TIME_LIMIT"] = None

Session(app)
csrf.init_app(app)

from .routes.analysis import bp_analysis
from .routes.api import bp_api
from .routes.auth import bp_auth
from .routes.dashboard import bp_dashboard
from .routes.logs import bp_logs
from .routes.system import bp_system
from .routes.tools import bp_tools

app.register_blueprint(bp_dashboard)
app.register_blueprint(bp_api, url_prefix="/api")
app.register_blueprint(bp_auth, url_prefix="/auth")
app.register_blueprint(bp_system, url_prefix="/system")
app.register_blueprint(bp_tools, url_prefix="/tools")
app.register_blueprint(bp_analysis, url_prefix="/analysis")
app.register_blueprint(bp_logs)

# ITAI Hub integration middleware (active only when ITAI_MODE=true)
from .middleware.itai import bp_itai, register_itai_middleware

register_itai_middleware(app)

# Rate limiting on login endpoint (10 attempts per minute per IP)
limiter.limit("10/minute")(app.view_functions.get("auth.login"))

# Rate limiting on DDEI Basic Auth endpoint (20 attempts per minute per IP)
# Prevents brute-force attacks against the machine-to-machine Basic Auth path.
if HAS_LIMITER:
    _ddei_view = app.view_functions.get("api.ddei_submit")
    if _ddei_view:
        limiter.limit("20/minute")(_ddei_view)

# Exempt machine-to-machine endpoints from CSRF.
# ALL endpoints in this list MUST use @api_key_required or @basic_auth_required
# (never @login_required alone) — CSRF protection is replaced by API-key auth.
csrf.exempt(bp_itai)  # SSO endpoint uses JWT

# API-key-only endpoints: firewall/SOAR/deceptor M2M integrations
for endpoint in [
    "add_indicator",       # @api_key_required
    "remove_indicator",    # @api_key_required
    "deceptor_block",      # @api_key_required
    "deceptor_unblock",    # @api_key_required
    "get_firewall_edl",    # public (no auth required)
    "get_saved_custom_edl",  # public (token-based)
    "get_generic_edl",     # @api_key_required
]:
    view = app.view_functions.get(f"api.{endpoint}")
    if view:
        csrf.exempt(view)


from flask_wtf.csrf import CSRFError


@app.errorhandler(CSRFError)
def handle_csrf_error(e):
    """CSRF doğrulama başarısız — login sayfasına yönlendir ve kullanıcıyı bilgilendir."""
    from flask import flash, redirect, request, url_for

    logger.warning("CSRF validation failed for %s %s from %s: %s", request.method, request.path, request.remote_addr, e.description)
    flash("Oturumunuz sona erdi veya geçersiz bir istek algılandı. Lütfen tekrar deneyin.", "warning")
    return redirect(url_for("auth.login"))


@app.route("/health")
def health_check():
    """Enhanced health check with DB and scheduler status."""
    health = {"status": "healthy", "version": __version__}
    try:
        from .database.connection import get_db_connection

        conn = get_db_connection()
        conn.execute("SELECT 1")
        conn.close()
        health["database"] = "connected"
    except Exception as e:
        logger.error(f"Health check DB error: {e}")
        health["database"] = "error"
        health["status"] = "degraded"

    try:
        from .scheduler_manager import scheduler

        health["scheduler"] = "running" if scheduler.running else "stopped"
        health["scheduled_jobs"] = len(scheduler.get_jobs())
    except Exception:
        health["scheduler"] = "unavailable"

    try:
        from .services.job_service import job_service

        health["aggregation_status"] = job_service.aggregation_status
    except Exception as _je:
        logger.debug("Health check: job_service unavailable: %s", _je)

    return api_response(health)


@app.route("/metrics")
def prometheus_metrics():
    """Prometheus-compatible metrics endpoint."""
    try:
        from prometheus_client import CONTENT_TYPE_LATEST, CollectorRegistry, Gauge, generate_latest

        from .db_manager import get_indicator_counts_by_type, get_unique_indicator_count
        from .services.feed_health import get_all_health_statuses

        registry = CollectorRegistry()

        total = Gauge("tfa_indicators_total", "Total indicator count", registry=registry)
        total.set(get_unique_indicator_count())

        counts = get_indicator_counts_by_type()
        for itype, count in counts.items():
            g = Gauge(f"tfa_indicators_{itype}", f"{itype} indicator count", registry=registry)
            g.set(count)

        health = get_all_health_statuses()
        disabled = Gauge("tfa_feeds_disabled", "Number of disabled feeds", registry=registry)
        disabled.set(sum(1 for v in health.values() if v.get("disabled_at")))

        from flask import Response

        return Response(generate_latest(registry), mimetype=CONTENT_TYPE_LATEST)
    except Exception as e:
        return api_response({"error": str(e)}, status=500)


@app.context_processor
def inject_version():
    return {"version": __version__}


LOCK_FILE = os.path.join(DATA_DIR, "scheduler.lock")

_scheduler_lock_fh = None  # Must survive GC to hold the OS file lock


def _start_scheduler():
    """Start APScheduler and sync jobs from config."""
    from .scheduler_manager import scheduler, update_scheduled_jobs

    if not scheduler.running:
        scheduler.start()
    update_scheduled_jobs()


def init_scheduler_safe():
    global _scheduler_lock_fh
    try:
        import fcntl

        _scheduler_lock_fh = open(LOCK_FILE, "w")
        fcntl.lockf(_scheduler_lock_fh, fcntl.LOCK_EX | fcntl.LOCK_NB)
        logger.info("MASTER LOCK ACQUIRED. Starting scheduler master process...")
        _start_scheduler()
        return True
    except (OSError, ImportError):
        if sys.platform == "win32":
            _start_scheduler()
            return True
        return False


# Start scheduler: in gunicorn only the lock-winner runs it;
# outside gunicorn (dev server) always start it.
if os.environ.get("GUNICORN_WORKER") == "1":
    init_scheduler_safe()
else:
    _start_scheduler()

if __name__ == "__main__":
    init_db()
    port = int(os.environ.get("PORT", 8080))
    app.run(host="0.0.0.0", port=port, debug=os.environ.get("FLASK_DEBUG", "0") == "1")
