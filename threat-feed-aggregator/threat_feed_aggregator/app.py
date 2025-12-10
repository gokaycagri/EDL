from flask import Flask, render_template, redirect, url_for, send_from_directory, request, jsonify, session
from functools import wraps
import os
import json
import threading
from datetime import datetime, timezone
from tzlocal import get_localzone
from apscheduler.schedulers.background import BackgroundScheduler
from apscheduler.jobstores.sqlalchemy import SQLAlchemyJobStore
from apscheduler.triggers.interval import IntervalTrigger # Added for type checking


# It's important to import the main function from your script.
from .aggregator import main as run_aggregator, aggregate_single_source
from .output_formatter import format_for_palo_alto, format_for_fortinet

app = Flask(__name__)
app.secret_key = 'a_very_secret_and_static_key_for_testing_do_not_use_in_production'
app.config['SESSION_COOKIE_NAME'] = 'threat_feed_aggregator_session'

# Define paths
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DATA_DIR = os.path.join(BASE_DIR, "data")
CONFIG_FILE = os.path.join(BASE_DIR, "config", "config.json")
DB_FILE = os.path.join(DATA_DIR, "db.json") # Add DB_FILE path here for JsonStore
STATS_FILE = os.path.join(BASE_DIR, "stats.json")

# Initialize scheduler
jobstores = {
    'default': SQLAlchemyJobStore(url=f'sqlite:///{DATA_DIR}/jobs.sqlite') # New file for scheduled jobs
}
scheduler = BackgroundScheduler(jobstores=jobstores)

# Global variables
AGGREGATION_STATUS = "idle"  # idle, running, completed

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

def update_scheduled_jobs():
    """
    Manages APScheduler jobs based on the current configuration in config.json.
    Adds, updates, or removes jobs for individual threat feed sources.
    """
    config = read_config()
    configured_sources = {source['name']: source for source in config.get('source_urls', [])}

    # Remove jobs that are no longer configured or whose schedule has changed
    for job in scheduler.get_jobs():
        # Ensure job.args is not empty before accessing its elements
        if not job.args or 'name' not in job.args[0]:
            print(f"Skipping malformed job {job.id}")
            continue

        job_source_name = job.args[0]['name'] # Assuming 'source_config' is the first arg
        current_interval = None
        if isinstance(job.trigger, IntervalTrigger): # Check if it's an IntervalTrigger
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
                    replace_existing=True # Update if already exists, useful for config changes
                )
                print(f"Scheduled job for {source_name} to run every {interval_minutes} minutes.")
            else:
                # Job exists, check if interval changed and update if necessary
                if existing_job.trigger.interval.total_seconds() / 60 != interval_minutes:
                    scheduler.reschedule_job(job_id, trigger='interval', minutes=interval_minutes)
                    print(f"Rescheduled job for {source_name} to run every {interval_minutes} minutes.")

def write_config(config):
    with open(CONFIG_FILE, "w") as f:
        json.dump(config, f, indent=4)
    update_scheduled_jobs() # Call after writing config

def read_db():
    print(f"DEBUG(app): Attempting to read DB from {DB_FILE}")
    if not os.path.exists(DB_FILE):
        print(f"DEBUG(app): {DB_FILE} not found. Returning empty indicators.")
        return {"indicators": {}}
    with open(DB_FILE, "r") as f:
        try:
            db_data = json.load(f)
            print(f"DEBUG(app): DB read successfully. Indicators count: {len(db_data.get('indicators', {}))}")
            return db_data
        except json.JSONDecodeError:
            print(f"DEBUG(app): Error decoding JSON from {DB_FILE}. Returning empty indicators.")
            return {"indicators": {}}

def read_stats():
    if not os.path.exists(STATS_FILE):
        return {}
    with open(STATS_FILE, "r") as f:
        try:
            stats = json.load(f)
            if isinstance(stats, dict):
                # Ensure all values are dictionaries
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
        if request.form['username'] != 'admin' or request.form['password'] != '123456':
            error = 'Invalid Credentials. Please try again.'
        else:
            session['logged_in'] = True
            session.modified = True
            print(f"DEBUG: Session after login: {session}")
            return redirect(url_for('index'))
    return render_template('login.html', error=error)

@app.route('/logout')
def logout():
    session.pop('logged_in', None)
    return redirect(url_for('index'))

@app.route('/')
def index():
    print(f"DEBUG: Session content in index: {session}")
    config = read_config()
    stats = read_stats()
    db_data = read_db() # Read db.json
    unique_ip_count = len(db_data.get("indicators", {})) # Calculate unique IP count
    print(f"DEBUG(app): Unique IP Count before rendering: {unique_ip_count}")

    local_tz = get_localzone() # Get local timezone once

    # Format timestamps in stats for display
    formatted_stats = {}
    for key, value in stats.items():
        if isinstance(value, dict) and 'last_updated' in value and value['last_updated'] != 'N/A':
            try:
                dt_obj = datetime.fromisoformat(value['last_updated'])
                formatted_stats[key] = {**value, 'last_updated': dt_obj.astimezone(local_tz).strftime('%d/%m/%Y %H:%M')} # Converted to local_tz
            except (ValueError, TypeError):
                formatted_stats[key] = value
        elif key == 'last_updated' and value != 'N/A':
            if isinstance(value, str):
                try:
                    dt_obj = datetime.fromisoformat(value)
                    formatted_stats[key] = dt_obj.astimezone(local_tz).strftime('%d/%m/%Y %H:%M') # Converted to local_tz
                except (ValueError, TypeError):
                    formatted_stats[key] = value
            else:
                formatted_stats[key] = value
        else:
            formatted_stats[key] = value

    scheduled_jobs = scheduler.get_jobs() # Get scheduled jobs
    # Prepare jobs for template
    jobs_for_template = []
    for job in scheduled_jobs:
        jobs_for_template.append({
            'id': job.id,
            'name': job.name,
            'next_run_time': job.next_run_time.astimezone(local_tz).strftime('%d/%m/%Y %H:%M') if job.next_run_time else 'N/A', # Converted to local_tz
            'interval': f"{job.trigger.interval.total_seconds() / 60} minutes" if isinstance(job.trigger, IntervalTrigger) else 'N/A'
        })

    return render_template('index.html', config=config, urls=config.get("source_urls", []), stats=formatted_stats, scheduled_jobs=jobs_for_template, unique_ip_count=unique_ip_count) # Pass formatted stats and jobs to template

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
            else: # If schedule_interval_minutes is empty, remove it from config
                if "schedule_interval_minutes" in updated_source:
                    del updated_source["schedule_interval_minutes"]
            config["source_urls"][index] = updated_source
            write_config(config) # This updates the scheduler

            # Trigger an immediate fetch for the updated source in a separate thread
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

def fetch_and_process_single_feed(source_config):
    """
    Fetches and processes data for a single threat feed source, updates DB and stats,
    then updates the output files (Palo Alto, Fortinet) based on the current full DB.
    This function is designed to be run by the scheduler for individual sources.
    """
    name = source_config["name"]
    print(f"Starting scheduled fetch for {name}...")

    # Call the single source aggregation function from aggregator.py
    # This function now handles updating db.json and stats.json for the source
    aggregate_single_source(source_config)

    # After updating a single source, re-generate the full output files
    # This requires reading the entire indicators_db
    db = read_db() # Use read_db() to safely get data
    processed_data = list(db.get("indicators", {}).keys())

    # Format and save for Palo Alto
    palo_alto_output = format_for_palo_alto(processed_data)
    palo_alto_file_path = os.path.join(DATA_DIR, "palo_alto_edl.txt")
    with open(palo_alto_file_path, "w") as f:
        f.write(palo_alto_output)

    # Format and save for Fortinet
    fortinet_output = format_for_fortinet(processed_data)
    fortinet_file_path = os.path.join(DATA_DIR, "fortinet_edl.txt")
    with open(fortinet_file_path, "w") as f:
        f.write(fortinet_output)
    
    print(f"Completed scheduled fetch for {name}.")


def aggregation_task(update_status=True): # Modified aggregation_task
    """
    Runs a full aggregation of all configured threat feeds.
    If update_status is True, updates global AGGREGATION_STATUS.
    This is used for the 'run all' button or initial full scan.
    """
    global AGGREGATION_STATUS
    if update_status:
        AGGREGATION_STATUS = "running"
    
    config = read_config()
    source_urls = config.get("source_urls", [])

    # Use the refactored main from aggregator.py which now calls aggregate_single_source for each
    results = run_aggregator(source_urls) # This now orchestrates calls to aggregate_single_source
    
    # The stats.json is now updated by aggregate_single_source for each feed.
    # We still want to ensure the overall 'last_updated' in stats is current for the entire batch if run this way.
    current_stats = read_stats()
    current_stats["last_updated"] = datetime.now(timezone.utc).isoformat()
    write_stats(current_stats)

    # Output files are already updated by fetch_and_process_single_feed within run_aggregator's loop,
    # but we can ensure they are consistent by re-reading the latest db.json if needed,
    # or trust that aggregate_single_source handles it.
    # For now, relying on aggregate_single_source to update them.

    if update_status:
        AGGREGATION_STATUS = "completed"

@app.route('/run')
@login_required
def run_script():
    global AGGREGATION_STATUS
    AGGREGATION_STATUS = "running"
    # Run the aggregation script in a separate thread to avoid blocking the web server
    thread = threading.Thread(target=aggregation_task)
    thread.start()
    return jsonify({"status": "running"})

@app.route('/status')
@login_required
def status():
    return jsonify({"status": AGGREGATION_STATUS})

@app.route('/data/<path:filename>')
@login_required
def download_file(filename):
    return send_from_directory(DATA_DIR, filename, as_attachment=True)

if __name__ == '__main__':
    scheduler.start() # Start the scheduler
    update_scheduled_jobs() # Load initial jobs
    app.run(debug=True, use_reloader=False)
