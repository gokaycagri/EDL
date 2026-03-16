import json
import logging
import os
import sys

import redis

try:
    import werkzeug
    if not hasattr(werkzeug, 'exceptions'):
        import werkzeug.exceptions
        sys.modules['werkzeug.exceptions'] = werkzeug.exceptions
except ImportError:
    pass

from .config_manager import DATA_DIR
from .database.schema import init_db
from .log_manager import setup_memory_logging
from .response_helpers import api_response
from .version import __version__

setup_memory_logging()
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(name)s - %(message)s')
logger = logging.getLogger(__name__)

try:
    from flask_limiter import Limiter
    from flask_limiter.util import get_remote_address
    HAS_LIMITER = True
except ImportError:
    HAS_LIMITER = False
    logger.warning("flask_limiter not found. Rate limiting is disabled.")
    
    # Dummy Limiter class to prevent AttributeError
    class Limiter:
        def __init__(self, *args, **kwargs): pass
        def init_app(self, app): pass
        def limit(self, *args, **kwargs):
            return lambda f: f
    
    def get_remote_address(): return "127.0.0.1"

from flask import Flask, request, jsonify
from flask_session import Session
from flask_wtf.csrf import CSRFProtect

app = Flask(__name__)
csrf = CSRFProtect()
limiter = Limiter(get_remote_address, app=app, default_limits=[], storage_uri="memory://")

@app.template_filter('from_json')
def from_json_filter(value):
    try:
        return json.loads(value) if isinstance(value, str) else value
    except Exception:
        return value

_secret = os.environ.get('SECRET_KEY')
if not _secret:
    _secret = os.urandom(32).hex()
    logger.warning("SECRET_KEY not set — generated a random key. Sessions will not persist across restarts.")
app.config['SECRET_KEY'] = _secret
app.config['MAX_CONTENT_LENGTH'] = 100 * 1024 * 1024

if os.environ.get('REDIS_HOST'):
    app.config['SESSION_TYPE'] = 'redis'
    redis_host = os.environ['REDIS_HOST']
    redis_port = os.environ.get('REDIS_PORT', 6379)
    app.config['SESSION_REDIS'] = redis.from_url(f'redis://{redis_host}:{redis_port}')
else:
    app.config['SESSION_TYPE'] = 'filesystem'
    app.config['SESSION_FILE_DIR'] = os.path.join(DATA_DIR, 'flask_session')

session_timeout = int(os.environ.get('SESSION_TIMEOUT_MINUTES', 60))
app.config['SESSION_PERMANENT'] = True
app.config['PERMANENT_SESSION_LIFETIME'] = session_timeout * 60
app.config['SESSION_USE_SIGNER'] = True

Session(app)
csrf.init_app(app)

from .routes.analysis import bp_analysis
from .routes.api import bp_api
from .routes.auth import bp_auth
from .routes.dashboard import bp_dashboard
from .routes.system import bp_system
from .routes.tools import bp_tools

app.register_blueprint(bp_dashboard)
app.register_blueprint(bp_api, url_prefix='/api')
app.register_blueprint(bp_auth, url_prefix='/auth')
app.register_blueprint(bp_system, url_prefix='/system')
app.register_blueprint(bp_tools, url_prefix='/tools')
app.register_blueprint(bp_analysis, url_prefix='/analysis')

# ITAI Hub integration middleware (active only when ITAI_MODE=true)
from .middleware.itai import bp_itai, register_itai_middleware

register_itai_middleware(app)

# Rate limiting on login endpoint (10 attempts per minute per IP)
limiter.limit("10/minute")(app.view_functions.get('auth.login'))

# Exempt machine-to-machine endpoints from CSRF (they use API key / JWT auth, not cookies)
csrf.exempt(bp_itai)  # SSO endpoint uses JWT

# Exempt specific API-key-only views from CSRF after they're registered
for endpoint in ['add_indicator', 'remove_indicator', 'deceptor_block', 'deceptor_unblock',
                 'get_firewall_edl', 'get_saved_custom_edl', 'get_generic_edl']:
    view = app.view_functions.get(f'api.{endpoint}')
    if view:
        csrf.exempt(view)


@app.route('/health')
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
        health["database"] = f"error: {e}"
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
    except Exception:
        pass

    return api_response(health)


@app.route('/metrics')
def prometheus_metrics():
    """Prometheus-compatible metrics endpoint."""
    try:
        from prometheus_client import CONTENT_TYPE_LATEST, CollectorRegistry, Gauge, generate_latest

        from .db_manager import get_indicator_counts_by_type, get_unique_indicator_count
        from .services.feed_health import get_all_health_statuses

        registry = CollectorRegistry()

        total = Gauge('tfa_indicators_total', 'Total indicator count', registry=registry)
        total.set(get_unique_indicator_count())

        counts = get_indicator_counts_by_type()
        for itype, count in counts.items():
            g = Gauge(f'tfa_indicators_{itype}', f'{itype} indicator count', registry=registry)
            g.set(count)

        health = get_all_health_statuses()
        disabled = Gauge('tfa_feeds_disabled', 'Number of disabled feeds', registry=registry)
        disabled.set(sum(1 for v in health.values() if v.get('disabled_at')))

        from flask import Response
        return Response(generate_latest(registry), mimetype=CONTENT_TYPE_LATEST)
    except Exception as e:
        return api_response({"error": str(e)}, status=500)

@app.context_processor
def inject_version():
    return {'version': __version__}

LOCK_FILE = os.path.join(DATA_DIR, 'scheduler.lock')

def init_scheduler_safe():
    try:
        import fcntl
        f = open(LOCK_FILE, 'w')
        fcntl.lockf(f, fcntl.LOCK_EX | fcntl.LOCK_NB)
        from .scheduler_manager import init_scheduler
        logger.info('MASTER LOCK ACQUIRED. Starting scheduler master process...')
        init_scheduler()
        return True
    except (OSError, ImportError):
        if sys.platform == 'win32':
            from .scheduler_manager import init_scheduler
            init_scheduler()
            return True
        return False

if os.environ.get('GUNICORN_WORKER') != '1' or init_scheduler_safe():
    pass

if __name__ == '__main__':
    init_db()
    port = int(os.environ.get('PORT', 8080))
    app.run(host='0.0.0.0', port=port, debug=os.environ.get('FLASK_DEBUG', '0') == '1')
