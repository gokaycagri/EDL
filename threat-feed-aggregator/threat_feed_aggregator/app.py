import logging
import os
import sys
import redis
import json

try:
    import werkzeug
    if not hasattr(werkzeug, 'exceptions'):
        import werkzeug.exceptions
        sys.modules['werkzeug.exceptions'] = werkzeug.exceptions
except ImportError:
    pass

from flask import Flask, request, jsonify
from flask_wtf.csrf import CSRFProtect
from flask_session import Session

from .config_manager import DATA_DIR
from .db_manager import init_db
from .log_manager import setup_memory_logging
from .response_helpers import api_response
from .version import __version__

setup_memory_logging()
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(name)s - %(message)s')
logger = logging.getLogger(__name__)

app = Flask(__name__)
csrf = CSRFProtect()

@app.template_filter('from_json')
def from_json_filter(value):
    try:
        return json.loads(value) if isinstance(value, str) else value
    except:
        return value

app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'default_secret_key')
app.config['MAX_CONTENT_LENGTH'] = 100 * 1024 * 1024
app.config['WTF_CSRF_CHECK_DEFAULT'] = False

if os.environ.get('REDIS_HOST'):
    app.config['SESSION_TYPE'] = 'redis'
    app.config['SESSION_REDIS'] = redis.from_url(f'redis://{os.environ['REDIS_HOST']}:{os.environ.get('REDIS_PORT', 6379)}')
else:
    app.config['SESSION_TYPE'] = 'filesystem'
    app.config['SESSION_FILE_DIR'] = os.path.join(DATA_DIR, 'flask_session')

app.config['SESSION_PERMANENT'] = False
app.config['SESSION_USE_SIGNER'] = True

Session(app)
csrf.init_app(app)

from .routes.dashboard import bp_dashboard
from .routes.api import bp_api
from .routes.auth import bp_auth
from .routes.system import bp_system
from .routes.tools import bp_tools
from .routes.analysis import bp_analysis

app.register_blueprint(bp_dashboard)
app.register_blueprint(bp_api, url_prefix='/api')
app.register_blueprint(bp_auth, url_prefix='/auth')
app.register_blueprint(bp_system, url_prefix='/system')
app.register_blueprint(bp_tools, url_prefix='/tools')
app.register_blueprint(bp_analysis, url_prefix='/analysis')

# ITAI Hub integration middleware (active only when ITAI_MODE=true)
from .middleware.itai import register_itai_middleware
register_itai_middleware(app)

@app.route('/health')
def health_check():
    return api_response({"health": "healthy", "version": __version__})

@app.context_processor
def inject_version():
    return {'version': __version__}

LOCK_FILE = os.path.join(DATA_DIR, 'scheduler.lock')

def init_scheduler_safe():
    import fcntl
    try:
        f = open(LOCK_FILE, 'w')
        fcntl.lockf(f, fcntl.LOCK_EX | fcntl.LOCK_NB)
        from .scheduler_manager import init_scheduler
        logger.info('MASTER LOCK ACQUIRED. Starting scheduler master process...')
        init_scheduler()
        return True
    except (IOError, ImportError):
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
    app.run(host='0.0.0.0', port=port, debug=True)
