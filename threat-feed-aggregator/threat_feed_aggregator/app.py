import logging
import os
import sys
import redis

# Werkzeug 3.x / Python 3.13 Compatibility Shim
try:
    import werkzeug
    if not hasattr(werkzeug, 'exceptions'):
        import werkzeug.exceptions
        sys.modules['werkzeug.exceptions'] = werkzeug.exceptions
except ImportError:
    pass

from flask import Flask, request
from flask_wtf.csrf import CSRFProtect
from flask_session import Session

from .cert_manager import generate_self_signed_cert, get_cert_paths
from .config_manager import DATA_DIR
from .db_manager import init_db
from .log_manager import setup_memory_logging
from .version import __version__

# Initialize Logging
setup_memory_logging()
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(name)s - %(message)s')

app = Flask(__name__)
csrf = CSRFProtect()

# --- Config ---
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'default_secret_key')
app.config['MAX_CONTENT_LENGTH'] = 100 * 1024 * 1024
app.config['WTF_CSRF_CHECK_DEFAULT'] = False # Python 3.13 compatibility

# Session Setup
if os.environ.get('REDIS_HOST'):
    app.config['SESSION_TYPE'] = 'redis'
    app.config['SESSION_REDIS'] = redis.from_url(f"redis://{os.environ['REDIS_HOST']}:{os.environ.get('REDIS_PORT', 6379)}")
else:
    app.config['SESSION_TYPE'] = 'filesystem'
    app.config['SESSION_FILE_DIR'] = os.path.join(DATA_DIR, 'flask_session')

app.config['SESSION_PERMANENT'] = False
app.config['SESSION_USE_SIGNER'] = True

# Initialize components safely
with app.app_context():
    if not os.path.exists(DATA_DIR): os.makedirs(DATA_DIR)
    init_db()
    
    # Session safely
    try:
        s_type = app.config.get('SESSION_TYPE')
        if s_type and isinstance(s_type, str) and not s_type.startswith('<MagicMock'):
            Session(app)
    except: pass
    
    csrf.init_app(app)

# --- Scheduler ---
from .scheduler_manager import scheduler, update_scheduled_jobs
if not scheduler.running:
    scheduler.start()
    update_scheduled_jobs()

# --- Routes & Blueprints ---
from .routes import bp_api, bp_auth, bp_dashboard, bp_system
from .routes.tools import bp_tools
from .routes.analysis import bp_analysis

app.register_blueprint(bp_dashboard)
app.register_blueprint(bp_api) 
app.register_blueprint(bp_auth)
app.register_blueprint(bp_system)
app.register_blueprint(bp_tools)
app.register_blueprint(bp_analysis)

from .routes.api import run_script, status
app.add_url_rule('/status', view_func=status)
app.add_url_rule('/run', view_func=run_script)

# --- Middlewares ---
@app.before_request
def protect_csrf():
    protected = ['auth', 'dashboard', 'system', 'tools', 'analysis']
    if request.blueprint in protected and request.method == "POST":
        if not request.endpoint.startswith('api.'):
            csrf.protect()

@app.context_processor
def inject_version():
    return dict(version=__version__)

@app.template_filter('from_json')
def from_json_filter(value):
    import json
    try: return json.loads(value)
    except: return {}

# Ensure SSL
generate_self_signed_cert()

if __name__ == '__main__':
    cert_file, key_file = get_cert_paths()
    port = int(os.environ.get("PORT", 443))
    app.run(debug=True, use_reloader=False, ssl_context=(cert_file, key_file), host='0.0.0.0', port=port)
