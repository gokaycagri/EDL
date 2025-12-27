import logging
import os
from flask import Flask, redirect, url_for
from apscheduler.schedulers.background import BackgroundScheduler
from apscheduler.jobstores.sqlalchemy import SQLAlchemyJobStore
from apscheduler.triggers.interval import IntervalTrigger
from flask_wtf.csrf import CSRFProtect

from .config_manager import DATA_DIR, read_config
from .db_manager import init_db, set_admin_password, get_admin_password_hash
from .cert_manager import generate_self_signed_cert, get_cert_paths, get_ca_bundle_path
from .log_manager import setup_memory_logging
from .aggregator import fetch_and_process_single_feed, run_aggregator
from .version import __version__

# Initialize Memory Logging
setup_memory_logging()
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(name)s - %(message)s')

# Set CA Bundle if exists (for requests/aiohttp)
custom_ca_bundle = get_ca_bundle_path()
if custom_ca_bundle:
    os.environ['REQUESTS_CA_BUNDLE'] = custom_ca_bundle
    os.environ['SSL_CERT_FILE'] = custom_ca_bundle
    logging.info(f"Using custom CA bundle at: {custom_ca_bundle}")

app = Flask(__name__)

# Context processor to make version available to all templates
@app.context_processor
def inject_version():
    return dict(version=__version__)

# Validate Environment
SECRET_KEY = os.environ.get('SECRET_KEY')
ADMIN_PASSWORD_ENV = os.environ.get('ADMIN_PASSWORD')

if not SECRET_KEY:
    logging.error("Environment variable 'SECRET_KEY' is not set. Please set it for production use.")
    SECRET_KEY = 'dev_key_do_not_use_in_production'
    
app.secret_key = os.getenv('SECRET_KEY', 'default_secret_key')

# Jinja2 Filters
@app.template_filter('from_json')
def from_json_filter(value):
    import json
    try:
        return json.loads(value)
    except:
        return {}

# CSRF Protection
csrf = CSRFProtect(app)
app.config['MAX_CONTENT_LENGTH'] = 2 * 1024 * 1024
app.config['SESSION_COOKIE_SECURE'] = False
app.config['SESSION_COOKIE_HTTPONLY'] = False
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'

# Data Directory
if not os.path.exists(DATA_DIR):
    os.makedirs(DATA_DIR)

# Database
init_db()

# Admin Password Init
if ADMIN_PASSWORD_ENV:
    if not get_admin_password_hash():
        success, msg = set_admin_password(ADMIN_PASSWORD_ENV)
        if success:
            logging.info("Admin password initialized from ENV.")
        else:
            logging.error(f"Failed to set initial admin password: {msg}")

# Scheduler
jobstores = {
    'default': SQLAlchemyJobStore(url=f'sqlite:///{os.path.join(DATA_DIR, "jobs.sqlite")}')
}
scheduler = BackgroundScheduler(jobstores=jobstores)

def update_scheduled_jobs():
    """Refreshes the scheduler jobs based on current config."""
    config = read_config()
    configured_sources = {source['name']: source for source in config.get('source_urls', [])}

    scheduler.remove_all_jobs()

    for source_name, source_config in configured_sources.items():
        interval_minutes = source_config.get('schedule_interval_minutes')
        if interval_minutes:
            job_id = f"feed_fetch_{source_name}"
            scheduler.add_job(
                fetch_and_process_single_feed,
                'interval',
                minutes=interval_minutes,
                id=job_id,
                name=source_name,
                args=[source_config],
                replace_existing=True
            )
            print(f"Scheduled job for {source_name} to run every {interval_minutes} minutes.")

# Ensure SSL
generate_self_signed_cert()

# Register Blueprints
from .routes import bp_dashboard, bp_api, bp_auth, bp_system
from .routes.tools import bp_tools
app.register_blueprint(bp_dashboard)
app.register_blueprint(bp_api) # Prefix /api
app.register_blueprint(bp_auth)
app.register_blueprint(bp_system)
app.register_blueprint(bp_tools)

# Special Route handling to keep /status and /run compatible with existing JS
# Or we can simply add alias routes here
from .routes.api import status, run_script
app.add_url_rule('/status', view_func=status)
app.add_url_rule('/run', view_func=run_script)

# Start Scheduler
if not scheduler.running:
    scheduler.start()
    update_scheduled_jobs()

if __name__ == '__main__':
    cert_file, key_file = get_cert_paths()
    port = int(os.environ.get("PORT", 443))
    app.run(debug=True, use_reloader=False, ssl_context=(cert_file, key_file), host='0.0.0.0', port=port)