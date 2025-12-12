import logging
import os
import json
import threading
from datetime import datetime, timezone
from functools import wraps

# Configure root logger immediately
logging.basicConfig(level=logging.DEBUG, format='%(asctime)s - %(levelname)s - %(name)s - %(message)s')

from flask import Flask, render_template, redirect, url_for, send_from_directory, request, jsonify, session, flash
from tzlocal import get_localzone
from apscheduler.schedulers.background import BackgroundScheduler
from apscheduler.jobstores.sqlalchemy import SQLAlchemyJobStore
from apscheduler.triggers.interval import IntervalTrigger
from flask_wtf.csrf import CSRFProtect

# Import refactored modules
from .aggregator import main as run_aggregator, aggregate_single_source, fetch_and_process_single_feed
from .output_formatter import format_for_palo_alto, format_for_fortinet
from .db_manager import init_db, get_all_indicators, get_unique_ip_count, get_whitelist, add_whitelist_item, remove_whitelist_item, delete_whitelisted_indicators, get_country_stats
from .cert_manager import generate_self_signed_cert, process_pfx_upload, get_cert_paths
from .auth_manager import check_credentials

app = Flask(__name__)
# Use environment variable for secret key, fallback for dev
app.secret_key = os.environ.get('SECRET_KEY', 'a_very_secret_and_static_key_for_testing_do_not_use_in_production')
app.config['SESSION_COOKIE_NAME'] = 'threat_feed_aggregator_session'

# SECURITY HARDENING
# 1. CSRF Protection
csrf = CSRFProtect(app)

# 2. File Upload Limit (Max 2MB)
app.config['MAX_CONTENT_LENGTH'] = 2 * 1024 * 1024

# 3. Secure Cookie Settings (Requires HTTPS)
app.config['SESSION_COOKIE_SECURE'] = False
app.config['SESSION_COOKIE_HTTPONLY'] = False
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'


# Define paths
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DATA_DIR = os.path.join(BASE_DIR, "data")
CONFIG_FILE = os.path.join(BASE_DIR, "threat_feed_aggregator", "config", "config.json")
STATS_FILE = os.path.join(BASE_DIR, "stats.json")

# Ensure data directory exists
if not os.path.exists(DATA_DIR):
    os.makedirs(DATA_DIR)

# Initialize scheduler
jobstores = {
    'default': SQLAlchemyJobStore(url=f'sqlite:///{os.path.join(DATA_DIR, "jobs.sqlite")}')
}
scheduler = BackgroundScheduler(jobstores=jobstores)

# Global variables
AGGREGATION_STATUS = "idle"  # idle, running, completed

# Initialize Database
init_db()

# Ensure SSL Certificates exist
generate_self_signed_cert()

def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'logged_in' not in session:
            return redirect(url_for('login', next=request.url))
        return f(*args, **kwargs)
    return decorated_function

def read_config():
    if not os.path.exists(CONFIG_FILE):
        return {"source_urls": []}
    with open(CONFIG_FILE, "r") as f:
        return json.load(f)

def write_config(config):
    with open(CONFIG_FILE, "w") as f:
        json.dump(config, f, indent=4)
    update_scheduled_jobs()

def update_scheduled_jobs():
    """
    Manages APScheduler jobs based on the current configuration in config.json.
    Adds, updates, or removes jobs for individual threat feed sources.
    """
    config = read_config()
    configured_sources = {source['name']: source for source in config.get('source_urls', [])}

    # Clear all existing jobs before re-adding them based on current config
    scheduler.remove_all_jobs()

    # Remove jobs that are no longer configured or whose schedule has changed
    for job in scheduler.get_jobs():
        if not job.args or 'name' not in job.args[0]:
            continue

        job_source_name = job.args[0]['name']
        current_interval = None
        if isinstance(job.trigger, IntervalTrigger):
            current_interval = job.trigger.interval.total_seconds() / 60

        if job_source_name not in configured_sources or \
           configured_sources[job_source_name].get('schedule_interval_minutes') != current_interval:
            scheduler.remove_job(job.id)
            print(f"Removed scheduled job for {job_source_name}.")

    # Add or update jobs for configured sources
    for source_name, source_config in configured_sources.items():
        interval_minutes = source_config.get('schedule_interval_minutes')
        if interval_minutes:
            job_id = f"feed_fetch_{source_name}"
            existing_job = scheduler.get_job(job_id)

            if not existing_job:
                scheduler.add_job(
                    fetch_and_process_single_feed,
                    'interval',
                    minutes=interval_minutes,
                    id=job_id,
                    args=[source_config],
                    replace_existing=True
                )
                print(f"Scheduled job for {source_name} to run every {interval_minutes} minutes.")
            else:
                if existing_job.trigger.interval.total_seconds() / 60 != interval_minutes:
                    scheduler.reschedule_job(job_id, trigger='interval', minutes=interval_minutes)
                    print(f"Rescheduled job for {source_name} to run every {interval_minutes} minutes.")

def read_stats():
    if not os.path.exists(STATS_FILE):
        return {}
    with open(STATS_FILE, "r") as f:
        try:
            stats = json.load(f)
            if isinstance(stats, dict):
                for key, value in stats.items():
                    if not isinstance(value, dict):
                        stats[key] = {}
                return stats
        except json.JSONDecodeError:
            pass
    return {}

def write_stats(stats):
    with open(STATS_FILE, "w") as f:
        json.dump(stats, f, indent=4)

@app.route('/login', methods=['GET', 'POST'])
def login():
    error = None
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        
        # Use auth_manager to check credentials (Local or LDAP)
        success, message = check_credentials(username, password)
        
        if success:
            session['logged_in'] = True
            session['username'] = username # Store username for display
            session.modified = True
            return redirect(url_for('index'))
        else:
            error = message if message else 'Invalid Credentials.'

    return render_template('login.html', error=error)

@app.route('/logout')
def logout():
    session.pop('logged_in', None)
    session.pop('username', None)
    return redirect(url_for('index'))

@app.route('/')
def index():
    config = read_config()
    stats = read_stats()
    
    # Get unique IP count from DB
    unique_ip_count = get_unique_ip_count()
    
    # Get Country Stats
    country_stats = get_country_stats()
    
    # Get Whitelist
    whitelist = get_whitelist()
    
    local_tz = get_localzone()

    # Format timestamps
    formatted_stats = {}
    for key, value in stats.items():
        if isinstance(value, dict) and 'last_updated' in value and value['last_updated'] != 'N/A':
            try:
                dt_obj = datetime.fromisoformat(value['last_updated'])
                formatted_stats[key] = {**value, 'last_updated': dt_obj.astimezone(local_tz).strftime('%d/%m/%Y %H:%M')}
            except (ValueError, TypeError):
                formatted_stats[key] = value
        elif key == 'last_updated' and value != 'N/A':
            if isinstance(value, str):
                try:
                    dt_obj = datetime.fromisoformat(value)
                    formatted_stats[key] = dt_obj.astimezone(local_tz).strftime('%d/%m/%Y %H:%M')
                except (ValueError, TypeError):
                    formatted_stats[key] = value
            else:
                formatted_stats[key] = value
        else:
            formatted_stats[key] = value

    scheduled_jobs = scheduler.get_jobs()
    jobs_for_template = []
    for job in scheduled_jobs:
        jobs_for_template.append({
            'id': job.id,
            'name': job.name,
            'next_run_time': job.next_run_time.astimezone(local_tz).strftime('%d/%m/%Y %H:%M') if job.next_run_time else 'N/A',
            'interval': f"{job.trigger.interval.total_seconds() / 60} minutes" if isinstance(job.trigger, IntervalTrigger) else 'N/A'
        })

    return render_template('index.html', config=config, urls=config.get("source_urls", []), stats=formatted_stats, scheduled_jobs=jobs_for_template, unique_ip_count=unique_ip_count, whitelist=whitelist, country_stats=country_stats)

@app.route('/add', methods=['POST'])
@login_required
def add_url():
    name = request.form.get('name')
    url = request.form.get('url')
    data_format = request.form.get('format', 'text')
    key_or_column = request.form.get('key_or_column')
    schedule_interval_minutes = request.form.get('schedule_interval_minutes', type=int)
    
    if name and url:
        config = read_config()
        new_source = {"name": name, "url": url, "format": data_format}
        if key_or_column:
            new_source["key_or_column"] = key_or_column
        if schedule_interval_minutes:
            new_source["schedule_interval_minutes"] = schedule_interval_minutes
        config["source_urls"].append(new_source)
        write_config(config)
    return redirect(url_for('index'))

@app.route('/update/<int:index>', methods=['POST'])
@login_required
def update_url(index):
    name = request.form.get('name')
    url = request.form.get('url')
    data_format = request.form.get('format', 'text')
    key_or_column = request.form.get('key_or_column')
    schedule_interval_minutes = request.form.get('schedule_interval_minutes', type=int)

    if name and url:
        config = read_config()
        if 0 <= index < len(config["source_urls"]):
            updated_source = {"name": name, "url": url, "format": data_format}
            if key_or_column:
                updated_source["key_or_column"] = key_or_column
            if schedule_interval_minutes:
                updated_source["schedule_interval_minutes"] = schedule_interval_minutes
            else:
                if "schedule_interval_minutes" in updated_source:
                    del updated_source["schedule_interval_minutes"]
            config["source_urls"][index] = updated_source
            write_config(config)

            thread = threading.Thread(target=fetch_and_process_single_feed, args=(updated_source,))
            thread.start()

    return redirect(url_for('index'))

@app.route('/remove/<int:index>')
@login_required
def remove_url(index):
    config = read_config()
    if 0 <= index < len(config["source_urls"]):
        config["source_urls"].pop(index)
        write_config(config)
    return redirect(url_for('index'))

@app.route('/update_settings', methods=['POST'])
@login_required
def update_settings():
    lifetime = request.form.get('indicator_lifetime_days')
    if lifetime:
        config = read_config()
        config['indicator_lifetime_days'] = int(lifetime)
        write_config(config)
    return redirect(url_for('index'))

@app.route('/update_ldap_settings', methods=['POST'])
@login_required
def update_ldap_settings():
    server = request.form.get('ldap_server')
    domain = request.form.get('ldap_domain')
    enabled = request.form.get('ldap_enabled') == 'on'
    
    config = read_config()
    if 'auth' not in config:
        config['auth'] = {}
    
    config['auth']['ldap'] = {
        'enabled': enabled,
        'server': server,
        'domain': domain
    }
    
    write_config(config)
    return redirect(url_for('index'))

@app.route('/upload_cert', methods=['POST'])
@login_required
def upload_cert():
    if 'pfx_file' not in request.files:
        flash('No file part')
        return redirect(url_for('index'))
    
    file = request.files['pfx_file']
    password = request.form.get('password', '')

    if file.filename == '':
        flash('No selected file')
        return redirect(url_for('index'))

    if file:
        file_content = file.read()
        success, message = process_pfx_upload(file_content, password)
        if success:
             pass
    return redirect(url_for('index'))

# --- Whitelist Routes ---

@app.route('/add_whitelist', methods=['POST'])
@login_required
def add_whitelist():
    item = request.form.get('item')
    description = request.form.get('description')
    
    if item:
        success, message = add_whitelist_item(item, description)
        if not success:
            flash(f'Error: {message}')
        else:
            # Immediate Cleanup: If we add a whitelist item, we should remove it from indicators db
            # This is a basic exact match cleanup. For CIDR, we'd need a heavier scan.
            delete_whitelisted_indicators([item])
            
    return redirect(url_for('index'))

@app.route('/remove_whitelist/<int:item_id>', methods=['GET']) # Using GET for simple link, POST better for safety
@login_required
def remove_whitelist(item_id):
    remove_whitelist_item(item_id)
    return redirect(url_for('index'))



def aggregation_task(update_status=True):
    """
    Runs a full aggregation of all configured threat feeds.
    """
    logging.debug(f"Starting aggregation_task (update_status={update_status}).")
    global AGGREGATION_STATUS
    if update_status:
        AGGREGATION_STATUS = "running"
    
    config = read_config()
    source_urls = config.get("source_urls", [])

    run_aggregator(source_urls)
    
    current_stats = read_stats()
    current_stats["last_updated"] = datetime.now(timezone.utc).isoformat()
    write_stats(current_stats)
    
    # Also update the output files after a full run
    indicators_data = get_all_indicators()
    processed_data = list(indicators_data.keys())
    
    palo_alto_output = format_for_palo_alto(processed_data)
    palo_alto_file_path = os.path.join(DATA_DIR, "palo_alto_edl.txt")
    with open(palo_alto_file_path, "w") as f:
        f.write(palo_alto_output)

    fortinet_output = format_for_fortinet(processed_data)
    fortinet_file_path = os.path.join(DATA_DIR, "fortinet_edl.txt")
    with open(fortinet_file_path, "w") as f:
        f.write(fortinet_output)

    if update_status:
        AGGREGATION_STATUS = "completed"
    logging.debug("aggregation_task completed.")

@app.route('/run')
# @login_required
def run_script():
    logging.debug("Received request to /run endpoint.")
    global AGGREGATION_STATUS
    if AGGREGATION_STATUS == "running":
        logging.info("Aggregation already running, returning status.")
        return jsonify({"status": AGGREGATION_STATUS})
    
    AGGREGATION_STATUS = "running"
    thread = threading.Thread(target=aggregation_task)
    thread.start()
    logging.info("Aggregation task started in a new thread.")
    return jsonify({"status": "running"})

@app.route('/status')
# @login_required
def status():
    logging.debug("Received request to /status endpoint.")
    return jsonify({"status": AGGREGATION_STATUS})

@app.route('/data/<path:filename>')
@login_required
def download_file(filename):
    return send_from_directory(DATA_DIR, filename, as_attachment=True)

# Start scheduler when app loads (for Gunicorn support with single worker)
# Note: With multiple workers, this would cause duplicate jobs.
if not scheduler.running:
    scheduler.start()
    update_scheduled_jobs()

if __name__ == '__main__':
    cert_file, key_file = get_cert_paths()
    # Enable SSL
    app.run(debug=True, use_reloader=False, ssl_context=(cert_file, key_file), host='0.0.0.0', port=443)
