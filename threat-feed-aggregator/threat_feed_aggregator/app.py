import logging
import os
import json
import threading
from datetime import datetime, timezone
from functools import wraps

# Configure root logger immediately
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(name)s - %(message)s')

from flask import Flask, render_template, redirect, url_for, send_from_directory, request, jsonify, session, flash
from tzlocal import get_localzone
from apscheduler.schedulers.background import BackgroundScheduler
from apscheduler.jobstores.sqlalchemy import SQLAlchemyJobStore
from apscheduler.triggers.interval import IntervalTrigger
from flask_wtf.csrf import CSRFProtect

from .config_manager import read_config, write_config, read_stats, write_stats, BASE_DIR, DATA_DIR, CONFIG_FILE, STATS_FILE
from .aggregator import main as run_aggregator, fetch_and_process_single_feed, CURRENT_JOB_STATUS, regenerate_edl_files
from .microsoft_services import process_microsoft_feeds
from .github_services import process_github_feeds
from .output_formatter import format_for_palo_alto, format_for_fortinet
from .db_manager import (
    init_db,
    get_all_indicators,
    get_unique_indicator_count,
    get_whitelist,
    add_whitelist_item,
    remove_whitelist_item,
    delete_whitelisted_indicators,
    get_country_stats,
    set_admin_password,
    check_admin_credentials,
    get_admin_password_hash,
    get_indicator_counts_by_type,
    get_job_history,
    clear_job_history
)
from .cert_manager import generate_self_signed_cert, process_pfx_upload, get_cert_paths
from .auth_manager import check_credentials
from .log_manager import setup_memory_logging, get_live_logs
from .utils import SAFE_ITEMS, add_to_safe_list, remove_from_safe_list # Updated imports

# Initialize Memory Logging to capture logs for GUI
setup_memory_logging()

app = Flask(__name__)

# Validate essential environment variables
SECRET_KEY = os.environ.get('SECRET_KEY')
ADMIN_PASSWORD_ENV = os.environ.get('ADMIN_PASSWORD')

if not SECRET_KEY:
    logging.error("Environment variable 'SECRET_KEY' is not set. Please set it for production use.")
    SECRET_KEY = 'a_very_secret_and_static_key_for_testing_do_not_use_in_production' # Fallback for dev
    
app.secret_key = SECRET_KEY
app.config['SESSION_COOKIE_NAME'] = 'threat_feed_aggregator_session'

# SECURITY HARDENING
csrf = CSRFProtect(app)
app.config['MAX_CONTENT_LENGTH'] = 2 * 1024 * 1024
app.config['SESSION_COOKIE_SECURE'] = False
app.config['SESSION_COOKIE_HTTPONLY'] = False
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'

# Ensure data directory exists
if not os.path.exists(DATA_DIR):
    os.makedirs(DATA_DIR)

# Initialize scheduler
jobstores = {
    'default': SQLAlchemyJobStore(url=f'sqlite:///{os.path.join(DATA_DIR, "jobs.sqlite")}')
}
scheduler = BackgroundScheduler(jobstores=jobstores)

# Global variables
AGGREGATION_STATUS = "idle"

# Initialize Database
init_db()

# Initialize admin password from ENV if DB is empty
if ADMIN_PASSWORD_ENV:
    if not get_admin_password_hash():
        success, msg = set_admin_password(ADMIN_PASSWORD_ENV)
        if success:
            logging.info("Admin password initialized from ADMIN_PASSWORD environment variable.")
        else:
            logging.error(f"Failed to set initial admin password from ENV: {msg}")
else:
    logging.warning("Environment variable 'ADMIN_PASSWORD' is not set.")

# Ensure SSL Certificates exist
generate_self_signed_cert()

def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'logged_in' not in session:
            return redirect(url_for('login', next=request.url))
        return f(*args, **kwargs)
    return decorated_function

def update_scheduled_jobs():
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
                args=[source_config],
                replace_existing=True
            )
            print(f"Scheduled job for {source_name} to run every {interval_minutes} minutes.")

@app.route('/login', methods=['GET', 'POST'])
def login():
    error = None
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        
        success, message = check_credentials(username, password)
        
        if success:
            session['logged_in'] = True
            session['username'] = username
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
@login_required
def index():
    config = read_config()
    stats = read_stats()
    
    total_indicator_count = get_unique_indicator_count()
    indicator_counts_by_type = get_indicator_counts_by_type()
    logging.info(f"Indicator Counts: {indicator_counts_by_type}") # Debug Log
    country_stats = get_country_stats()
    whitelist = get_whitelist()
    
    # Sort safe list for display
    safe_list_sorted = sorted(list(SAFE_ITEMS))
    
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

    scheduled_jobs = scheduler.get_jobs()
    jobs_for_template = []
    for job in scheduled_jobs:
        jobs_for_template.append({
            'id': job.id,
            'name': job.name,
            'next_run_time': job.next_run_time.astimezone(local_tz).strftime('%d/%m/%Y %H:%M') if job.next_run_time else 'N/A',
            'interval': f"{job.trigger.interval.total_seconds() / 60} minutes" if isinstance(job.trigger, IntervalTrigger) else 'N/A'
        })

    return render_template('index.html', config=config, urls=config.get("source_urls", []), stats=formatted_stats, scheduled_jobs=jobs_for_template, total_indicator_count=total_indicator_count, indicator_counts_by_type=indicator_counts_by_type, whitelist=whitelist, country_stats=country_stats, safe_list=safe_list_sorted)

@app.route('/api/status_detailed')
@login_required
def status_detailed():
    """Returns detailed status of currently running jobs."""
    return jsonify(CURRENT_JOB_STATUS)

@app.route('/api/history')
@login_required
def job_history():
    """Returns past job execution history."""
    history = get_job_history(limit=20)
    # Format dates
    local_tz = get_localzone()
    for item in history:
        try:
            start_dt = datetime.fromisoformat(item['start_time'])
            item['start_time'] = start_dt.astimezone(local_tz).strftime('%Y-%m-%d %H:%M:%S')
            if item['end_time']:
                end_dt = datetime.fromisoformat(item['end_time'])
                item['end_time'] = end_dt.astimezone(local_tz).strftime('%H:%M:%S')
                duration = (end_dt - start_dt).total_seconds()
                item['duration'] = f"{duration:.2f}s"
            else:
                item['duration'] = "Running..."
        except Exception:
            pass
    return jsonify(history)

@app.route('/api/history/clear', methods=['POST'])
@login_required
def clear_history_route():
    """Clears the job history."""
    if clear_job_history():
        return jsonify({'status': 'success', 'message': 'Job history cleared.'})
    else:
        return jsonify({'status': 'error', 'message': 'Failed to clear job history.'}), 500

@app.route('/api/live_logs')
@login_required
def live_logs():
    """Returns the latest logs from memory."""
    return jsonify(get_live_logs())

@app.route('/api/regenerate_lists', methods=['POST'])
@login_required
def api_regenerate_lists():
    success, msg = regenerate_edl_files()
    if success:
        return jsonify({'status': 'success', 'message': msg})
    else:
        return jsonify({'status': 'error', 'message': msg})

@app.route('/api/update_ms365', methods=['POST'])
@login_required
def api_update_ms365():
    """Triggers the Microsoft 365 feed update."""
    try:
        success, msg = process_microsoft_feeds()
        if success:
            return jsonify({'status': 'success', 'message': msg})
        else:
            return jsonify({'status': 'error', 'message': msg})
    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)})

@app.route('/api/update_github', methods=['POST'])
@login_required
def api_update_github():
    """Triggers the GitHub feed update."""
    try:
        success, msg = process_github_feeds()
        if success:
            return jsonify({'status': 'success', 'message': msg})
        else:
            return jsonify({'status': 'error', 'message': msg})
    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)})

@app.route('/api/safe_list/add', methods=['POST'])
@login_required
def add_safe_list_item():
    item = request.form.get('item')
    if item:
        success, message = add_to_safe_list(item)
        if success:
            flash(f'Added to Safe List: {item}', 'success')
        else:
            flash(f'Error adding to Safe List: {message}', 'danger')
    return redirect(url_for('index'))

@app.route('/api/safe_list/remove', methods=['POST'])
@login_required
def remove_safe_list_item():
    item = request.form.get('item')
    if item:
        success, message = remove_from_safe_list(item)
        if success:
            flash(f'Removed from Safe List: {item}', 'success')
        else:
            flash(f'Error removing from Safe List: {message}', 'danger')
    return redirect(url_for('index'))

@app.route('/add', methods=['POST'])
@login_required
def add_url():
    name = request.form.get('name')
    url = request.form.get('url')
    data_format = request.form.get('format', 'text')
    key_or_column = request.form.get('key_or_column')
    schedule_interval_minutes = request.form.get('schedule_interval_minutes', type=int)
    confidence = request.form.get('confidence', default=50, type=int)
    retention_days = request.form.get('retention_days', type=int)
    
    if name and url:
        config = read_config()
        new_source = {
            "name": name, 
            "url": url, 
            "format": data_format,
            "confidence": confidence
        }
        if key_or_column:
            new_source["key_or_column"] = key_or_column
        if schedule_interval_minutes:
            new_source["schedule_interval_minutes"] = schedule_interval_minutes
        if retention_days:
            new_source["retention_days"] = retention_days
            
        config["source_urls"].append(new_source)
        write_config(config)
        update_scheduled_jobs()
    return redirect(url_for('index'))

@app.route('/update/<int:index>', methods=['POST'])
@login_required
def update_url(index):
    name = request.form.get('name')
    url = request.form.get('url')
    data_format = request.form.get('format', 'text')
    key_or_column = request.form.get('key_or_column')
    schedule_interval_minutes = request.form.get('schedule_interval_minutes', type=int)
    confidence = request.form.get('confidence', default=50, type=int)
    retention_days = request.form.get('retention_days', type=int)

    if name and url:
        config = read_config()
        if 0 <= index < len(config["source_urls"]):
            updated_source = {
                "name": name, 
                "url": url, 
                "format": data_format,
                "confidence": confidence
            }
            if key_or_column:
                updated_source["key_or_column"] = key_or_column
            if schedule_interval_minutes:
                updated_source["schedule_interval_minutes"] = schedule_interval_minutes
            else:
                if "schedule_interval_minutes" in updated_source:
                    del updated_source["schedule_interval_minutes"]
            
            if retention_days:
                updated_source["retention_days"] = retention_days
            else:
                if "retention_days" in updated_source:
                    del updated_source["retention_days"]

            config["source_urls"][index] = updated_source
            write_config(config)
            
            update_scheduled_jobs()

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
        update_scheduled_jobs()
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
    server = request.form.get('ldap_server').replace('ldap://', '')
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
            delete_whitelisted_indicators([item])
            
    return redirect(url_for('index'))

@app.route('/remove_whitelist/<int:item_id>', methods=['GET'])
@login_required
def remove_whitelist(item_id):
    remove_whitelist_item(item_id)
    return redirect(url_for('index'))

@app.route('/change_admin_password', methods=['POST'])
@login_required
def change_admin_password():
    current_password = request.form.get('current_password')
    new_password = request.form.get('new_password')
    confirm_new_password = request.form.get('confirm_new_password')

    if not check_admin_credentials(current_password):
        flash('Current password is incorrect.', 'danger')
        return redirect(url_for('index'))
    
    if not new_password or new_password != confirm_new_password:
        flash('New passwords do not match or are empty.', 'danger')
        return redirect(url_for('index'))
    
    success, message = set_admin_password(new_password)
    if success:
        flash('Admin password updated successfully. Please re-login with your new password.', 'success')
        session.pop('logged_in', None)
        session.pop('username', None)
        return redirect(url_for('login'))
    else:
        flash(f'Error updating password: {message}', 'danger')
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
    
    # Logic for updating output files and stats is now handled within run_aggregator or separate functions
    # to avoid duplication, but app.py needs global state update.
    # run_aggregator updates db and returns stats.
    # We should ensure output files are also updated after full run.
    
    indicators_data = get_all_indicators()
    
    from .output_formatter import format_for_palo_alto, format_for_fortinet, format_for_url_list

    palo_alto_output = format_for_palo_alto(indicators_data)
    with open(os.path.join(DATA_DIR, "palo_alto_edl.txt"), "w") as f:
        f.write(palo_alto_output)

    fortinet_output = format_for_fortinet(indicators_data)
    with open(os.path.join(DATA_DIR, "fortinet_edl.txt"), "w") as f:
        f.write(fortinet_output)

    url_list_output = format_for_url_list(indicators_data)
    with open(os.path.join(DATA_DIR, "url_list.txt"), "w") as f:
        f.write(url_list_output)

    if update_status:
        AGGREGATION_STATUS = "completed"
    logging.debug("aggregation_task completed.")

@app.route('/run')
@login_required
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
@login_required
def status():
    logging.debug("Received request to /status endpoint.")
    return jsonify({"status": AGGREGATION_STATUS})

@app.route('/data/<path:filename>')
@login_required
def download_file(filename):
    return send_from_directory(DATA_DIR, filename, as_attachment=True)

# Start scheduler when app loads
if not scheduler.running:
    scheduler.start()
    update_scheduled_jobs()

if __name__ == '__main__':
    cert_file, key_file = get_cert_paths()
    app.run(debug=True, use_reloader=False, ssl_context=(cert_file, key_file), host='0.0.0.0', port=443)
