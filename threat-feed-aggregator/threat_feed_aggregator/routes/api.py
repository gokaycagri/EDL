import io
import csv
import json
import logging
import os
import threading
import time
import zipfile
from datetime import UTC, datetime, timedelta

import pytz
from flask import flash, jsonify, redirect, request, send_file, stream_with_context, url_for, Response

from ..aggregator import fetch_and_process_single_feed, regenerate_edl_files, run_aggregator, test_feed_source, trigger_background_regeneration
from ..scheduler_manager import scheduler, update_scheduled_jobs
from ..azure_services import process_azure_feeds
from ..microsoft_services import process_microsoft_feeds
from ..config_manager import DATA_DIR, read_config, read_stats
from ..db_manager import (
    add_api_blacklist_item,
    add_whitelist_item,
    clear_job_history,
    get_historical_stats,
    get_indicator_counts_by_type,
    get_job_history,
    get_unique_indicator_count,
    get_whitelist,
    remove_api_blacklist_item,
    remove_whitelist_item,
    get_all_indicators_iter,
    get_filtered_indicators_iter,
    get_custom_list_by_token,
    get_custom_list_count,
    upsert_indicators_bulk,
)
from ..github_services import process_github_feeds
from ..log_manager import clear_logs, get_live_logs
from ..response_helpers import api_error, api_response
from ..utils import add_to_safe_list, format_timestamp, remove_from_safe_list, validate_indicator
from ..services.job_service import job_service
from . import bp_api
from .auth import api_key_required, login_required

logger = logging.getLogger(__name__)

_DECEPTOR_PROBE_STRINGS = {"hacker-ip", "1", "test", "ping"}


def _build_type_filter(include_types):
    """Normalize type filters into a set for O(1) membership checks."""
    if not include_types:
        return None
    return {t.strip() for t in include_types if t and t.strip()}


def _sanitize_headers_for_log(headers):
    """Redact sensitive headers before logging request metadata."""
    redacted = dict(headers)
    for key in ("Authorization", "X-API-KEY", "Api-Key"):
        if key in redacted:
            redacted[key] = "<redacted>"
    return redacted


def _csv_row(values):
    """Serialize one CSV row without holding the whole output in memory."""
    buffer = io.StringIO()
    writer = csv.writer(buffer)
    writer.writerow(values)
    return buffer.getvalue()

CACHE_DIR = os.path.join(DATA_DIR, 'edl_cache')
if not os.path.exists(CACHE_DIR):
    os.makedirs(CACHE_DIR)

def _get_cached_edl_path(token, fmt):
    return os.path.join(CACHE_DIR, f"{token}.{fmt}")

def _is_cache_valid(path, ttl_seconds=600):
    if not os.path.exists(path):
        return False
    mtime = os.stat(path).st_mtime
    age = time.time() - mtime
    return age < ttl_seconds

@bp_api.route('/edl/firewall/<path:filename>', methods=['GET', 'HEAD'])
def get_firewall_edl(filename):
    """
    Public-ish endpoint for firewalls to fetch EDL files.
    Does NOT require session login.
    """
    from flask import send_from_directory, make_response
    
    # Security: Ensure we only serve .txt files (no path traversal)
    safe_filename = os.path.basename(filename)
    if not safe_filename.endswith('.txt'):
        return jsonify({'error': 'Invalid file type'}), 403

    from ..config_manager import DATA_DIR
    
    file_path = os.path.join(DATA_DIR, safe_filename)
    logger.info(f"Firewall EDL request: {safe_filename} from {request.remote_addr} (Method: {request.method})")
    
    if not os.path.exists(file_path):
        logger.error(f"Firewall EDL File NOT FOUND: {file_path}")
        return jsonify({'error': 'File not found'}), 404

    # Handle HEAD request for connector validation
    if request.method == 'HEAD':
        response = make_response('', 200)
        response.headers['Content-Type'] = 'text/plain'
        response.headers['Content-Length'] = os.path.getsize(file_path)
        return response

    response = make_response(send_from_directory(DATA_DIR, safe_filename, mimetype='text/plain'))
    # Disable caching to ensure firewalls get fresh data
    response.headers['Cache-Control'] = 'no-cache, no-store, must-revalidate'
    response.headers['Pragma'] = 'no-cache'
    response.headers['Expires'] = '0'
    return response


@bp_api.route('/custom_list/count/<int:list_id>')
@login_required
def custom_list_count_api(list_id):
    """Returns the item count for a custom list."""
    count = get_custom_list_count(list_id)
    return api_response({"count": count})

@bp_api.route('/edl/custom/<token>')
def get_saved_custom_edl(token):
    """
    Returns a saved custom EDL by its token.
    Uses file-based caching (10 mins) and streaming for performance.
    """
    list_config = get_custom_list_by_token(token)
    if not list_config:
        return jsonify({'error': 'List not found'}), 404

    output_format = list_config['format']
    cache_path = _get_cached_edl_path(token, output_format)

    # 1. Serve from Cache if valid
    if _is_cache_valid(cache_path):
        if output_format == 'text':
            mimetype = 'text/plain'
        elif output_format == 'json':
            mimetype = 'application/json'
        else:
            mimetype = 'text/csv'
        return send_file(cache_path, mimetype=mimetype)

    # 2. Regenerate Cache (Streaming)
    include_sources = list_config['sources']
    include_types = list_config['types']
    include_types_filter = _build_type_filter(include_types)
    
    try:
        iterator = get_filtered_indicators_iter(include_sources)
        
        # Write to temporary file then rename (atomic-ish)
        temp_path = cache_path + ".tmp"
        
        with open(temp_path, 'w', encoding='utf-8') as f:
            if output_format == 'text':
                # Optimized Stream for Text
                count = 0
                for row in iterator:
                    if not include_types_filter or row['type'] in include_types_filter:
                        f.write(row['indicator'] + '\n')
                        count += 1
                if count == 0:
                    logger.warning(f"Custom EDL ({token}) generated 0 records.")
            else:
                # Fallback for CSV/JSON (requires list structure usually)
                # But we can optimize CSV streaming
                if output_format == 'csv':
                    import csv
                    writer = csv.writer(f)
                    writer.writerow(['indicator', 'type', 'risk_score', 'country'])
                    for row in iterator:
                        if not include_types_filter or row['type'] in include_types_filter:
                            writer.writerow([row['indicator'], row['type'], row['risk_score'], row['country']])
                elif output_format == 'json':
                    # Write JSON incrementally to avoid holding large lists in memory.
                    first_item = True
                    f.write('[')
                    for row in iterator:
                        if not include_types_filter or row['type'] in include_types_filter:
                            if not first_item:
                                f.write(',\n')
                            f.write(json.dumps({
                                'indicator': row['indicator'],
                                'type': row['type'],
                                'risk_score': row['risk_score'],
                                'country': row['country']
                            }))
                            first_item = False
                    f.write(']')

        # Move temp file to cache path
        import shutil
        shutil.move(temp_path, cache_path)
        
        if output_format == 'text':
            mimetype = 'text/plain'
        elif output_format == 'json':
            mimetype = 'application/json'
        else:
            mimetype = 'text/csv'
        return send_file(cache_path, mimetype=mimetype)

    except Exception as e:
        logger.error(f"Error generating Custom EDL {token}: {e}")
        return jsonify({'error': 'Generation failed'}), 500


@bp_api.route('/edl/generic')
@api_key_required
def get_generic_edl():
    """
    Returns a generic EDL.
    Params:
    - types: comma separated (ip,domain,url,cidr)
    - format: text, csv, json
    - delimiter: for text format (default newline)
    """
    types_str = request.args.get('types')
    include_types = types_str.split(',') if types_str else None
    
    sources_str = request.args.get('sources')
    include_sources = sources_str.split(',') if sources_str and sources_str.strip() else None

    output_format = request.args.get('format', 'text')
    delimiter = request.args.get('delimiter', '\n')
    include_types_filter = _build_type_filter(include_types)
    
    # Validation
    if output_format not in ['text', 'csv', 'json']:
        return jsonify({'error': 'Invalid format'}), 400

    iterator = get_filtered_indicators_iter(include_sources)

    if output_format == 'text':
        @stream_with_context
        def generate_text():
            first_item = True
            for row in iterator:
                if include_types_filter and row['type'] not in include_types_filter:
                    continue
                if not first_item:
                    yield delimiter
                yield row['indicator']
                first_item = False

        return Response(generate_text(), mimetype='text/plain')

    if output_format == 'csv':
        @stream_with_context
        def generate_csv():
            yield _csv_row(['indicator', 'type', 'risk_score', 'country'])
            for row in iterator:
                if include_types_filter and row['type'] not in include_types_filter:
                    continue
                yield _csv_row([row['indicator'], row['type'], row['risk_score'], row['country']])

        return Response(generate_csv(), mimetype='text/csv')

    @stream_with_context
    def generate_json():
        first_item = True
        yield '['
        for row in iterator:
            if include_types_filter and row['type'] not in include_types_filter:
                continue
            if not first_item:
                yield ','
            yield json.dumps({
                'indicator': row['indicator'],
                'type': row['type'],
                'risk_score': row['risk_score'],
                'country': row['country']
            })
            first_item = False
        yield ']'

    return Response(generate_json(), mimetype='application/json')


def aggregation_task(update_status=True):
    """
    Runs a full aggregation of all configured threat feeds.
    """
    logging.debug(f"Starting aggregation_task (update_status={update_status}).")
    if update_status:
        job_service.aggregation_status = "running"

    config = read_config()
    source_urls = config.get("source_urls", [])

    run_aggregator(source_urls)

    if update_status:
        job_service.aggregation_status = "completed"
    logging.debug("aggregation_task completed.")


@bp_api.route('/run')
@login_required
def run_script():
    logging.debug("Received request to /api/run endpoint.")
    if job_service.aggregation_status == "running":
        logging.info("Aggregation already running, returning status.")
        return api_response({"aggregation_status": "running"}, message="Aggregation already running")

    job_service.aggregation_status = "running"
    thread = threading.Thread(target=aggregation_task)
    thread.start()
    logging.info("Aggregation task started in a new thread.")
    return api_response({"aggregation_status": "running"}, message="Aggregation started")


@bp_api.route('/run_single/<path:name>')
@login_required
def run_single_feed(name):
    """Triggers a single feed update in the background."""
    config = read_config()
    source = next((s for s in config.get('source_urls', []) if s['name'] == name), None)

    if not source:
        return api_error("Source not found", "SOURCE_NOT_FOUND", 404)

    thread = threading.Thread(target=fetch_and_process_single_feed, args=(source,))
    thread.start()

    return api_response({"source": name, "aggregation_status": "running"}, message=f"Fetch started for {name}")


@bp_api.route('/status')
@login_required
def status():
    logging.debug("Received request to /api/status endpoint.")
    return api_response({"aggregation_status": job_service.aggregation_status})


@bp_api.route('/status_detailed')
@login_required
def status_detailed():
    """Returns detailed status of currently running jobs."""
    return api_response(job_service.get_all_job_statuses())


@bp_api.route('/scheduled_jobs')
@login_required
def get_scheduled_jobs():
    """Returns sorted list of upcoming scheduled jobs."""
    config = read_config()
    target_tz = pytz.timezone(config.get('timezone', 'UTC'))

    jobs = scheduler.get_jobs()
    formatted_jobs = []

    for job in jobs:
        # Safely get next_run_time as it might not exist yet if job is being scheduled
        jt = getattr(job, 'next_run_time', None)
        next_run = jt.astimezone(target_tz) if jt else None
        time_until = 'N/A'
        if next_run:
            now = datetime.now(target_tz)
            diff = next_run - now
            total_seconds = int(diff.total_seconds())
            if total_seconds < 0:
                time_until = "Running..."
            else:
                minutes = total_seconds // 60
                if minutes < 60:
                    time_until = f"in {minutes} min"
                else:
                    hours = minutes // 60
                    mins = minutes % 60
                    time_until = f"in {hours}h {mins}m"

        formatted_jobs.append({
            'name': job.name,
            'next_run_time': next_run.strftime('%d/%m/%Y %H:%M') if next_run else 'N/A',
            'next_run_timestamp': next_run.timestamp() if next_run else 0,
            'time_until': time_until
        })

    # Sort by nearest run time
    formatted_jobs.sort(key=lambda x: x['next_run_timestamp'] if x['next_run_timestamp'] > 0 else float('inf'))

    return api_response({"items": formatted_jobs, "total": len(formatted_jobs)})


@bp_api.route('/trend_data')
@login_required
def trend_data():
    """Returns historical stats for the chart."""
    days = request.args.get('days', default=30, type=int)
    data = get_historical_stats(days)

    # Format dates for Chart.js using configured TZ
    formatted_data = []
    for row in data:
        try:
            row['timestamp'] = format_timestamp(row['timestamp'], fmt='%Y-%m-%d %H:%M')
            formatted_data.append(row)
        except Exception:
            pass

    return api_response({"items": formatted_data, "total": len(formatted_data)})


@bp_api.route('/history')
@login_required
def job_history():
    """Returns past job execution history."""
    limit = request.args.get('limit', default=20, type=int)
    history = get_job_history(limit=limit)
    # Format dates
    for item in history:
        try:
            # We need raw datetime objects for duration calculation before formatting
            start_dt = datetime.fromisoformat(item['start_time'])

            if item['end_time']:
                end_dt = datetime.fromisoformat(item['end_time'])
                duration = (end_dt - start_dt).total_seconds()
                item['duration'] = f"{duration:.2f}s"
                item['end_time'] = format_timestamp(item['end_time'], fmt='%H:%M:%S')
            else:
                item['duration'] = "Running..."

            item['start_time'] = format_timestamp(item['start_time'], fmt='%Y-%m-%d %H:%M:%S')
        except Exception:
            pass
    return api_response({"items": history, "total": len(history)})


@bp_api.route('/history/clear', methods=['POST'])
@login_required
def clear_history_route():
    """Clears the job history."""
    logger.info("RECEIVED request to clear job history")
    if clear_job_history():
        return api_response(message="Job history cleared.")
    else:
        logger.error("Failed to clear job history in DB")
        return api_error("Failed to clear job history.", "DB_ERROR", 500)


@bp_api.route('/live_logs')
@login_required
def live_logs():
    """Returns the latest logs from memory."""
    logs = get_live_logs()
    return api_response({"items": logs, "total": len(logs)})


@bp_api.route('/live_logs/clear', methods=['POST'])
@login_required
def clear_live_logs_route():
    """Clears the live logs from memory."""
    clear_logs()
    return api_response(message="Live logs cleared.")


@bp_api.route('/source_stats')
@login_required
def source_stats_api():
    """Returns current counts and last updated times for all sources."""
    from ..config_manager import read_config, read_stats
    from ..db_manager import (
        get_country_stats,
        get_indicator_counts_by_type,
        get_unique_indicator_count,
        get_source_counts,
        get_latest_job_times
    )

    stats = read_stats()
    config = read_config()

    total_count = get_unique_indicator_count()
    counts_by_type = get_indicator_counts_by_type()
    country_stats = get_country_stats()
    
    # Fetch real-time data from DB to ensure accuracy
    real_db_counts = get_source_counts()
    real_db_times = get_latest_job_times()

    formatted_stats = {}
    # 1. Process sources present in stats.json
    for name, data in stats.items():
        if name == 'last_updated':
            formatted_stats[name] = format_timestamp(data)
            continue

        if isinstance(data, dict):
            # Use DB count if available, otherwise fallback to stats file
            current_count = real_db_counts.get(name, data.get('count', 0))
            
            # Use DB timestamp if available, otherwise fallback
            last_ts = real_db_times.get(name, data.get('last_updated'))
            
            formatted_stats[name] = {
                "count": current_count,
                "last_updated": format_timestamp(last_ts)
            }
        else:
            formatted_stats[name] = data
            
    # 2. Ensure sources in DB (but maybe missing in stats.json) are included if they match config
    configured_sources = [s['name'] for s in config.get('source_urls', [])]
    
    # Merge keys from both DB counts and DB times to catch all active sources
    all_known_sources = set(real_db_counts.keys()) | set(real_db_times.keys())
    
    for name in all_known_sources:
        if name in configured_sources and name not in formatted_stats:
             formatted_stats[name] = {
                 "count": real_db_counts.get(name, 0),
                 "last_updated": format_timestamp(real_db_times.get(name))
             }

    return api_response({
        "sources": formatted_stats,
        "totals": {
            "total": total_count,
            "ip": counts_by_type.get('ip', 0) + counts_by_type.get('cidr', 0),
            "domain": counts_by_type.get('domain', 0) + counts_by_type.get('url', 0),
            "feeds": len(config.get('source_urls', []))
        },
        "country_stats": country_stats
    })


@bp_api.route('/regenerate_lists', methods=['POST'])
@login_required
def api_regenerate_lists():
    success, msg = regenerate_edl_files()
    if success:
        return api_response(message=msg)
    else:
        return api_error(msg, "REGENERATION_FAILED", 500)


@bp_api.route('/update_ms365', methods=['POST'])
@login_required
def api_update_ms365():
    try:
        success, msg = process_microsoft_feeds()
        if success:
            return api_response(message=msg)
        else:
            return api_error(msg, "MS365_UPDATE_FAILED", 500)
    except Exception as e:
        return api_error(str(e), "MS365_UPDATE_ERROR", 500)


@bp_api.route('/update_github', methods=['POST'])
@login_required
def api_update_github():
    try:
        success, msg = process_github_feeds()
        if success:
            return api_response(message=msg)
        else:
            return api_error(msg, "GITHUB_UPDATE_FAILED", 500)
    except Exception as e:
        return api_error(str(e), "GITHUB_UPDATE_ERROR", 500)


@bp_api.route('/update_azure', methods=['POST'])
@login_required
def api_update_azure():
    try:
        success, msg = process_azure_feeds()
        if success:
            return api_response(message=msg)
        else:
            return api_error(msg, "AZURE_UPDATE_FAILED", 500)
    except Exception as e:
        return api_error(str(e), "AZURE_UPDATE_ERROR", 500)


@bp_api.route('/backup', methods=['GET'])
@login_required
def backup_system():
    try:
        # Create in-memory zip
        memory_file = io.BytesIO()
        with zipfile.ZipFile(memory_file, 'w', zipfile.ZIP_DEFLATED) as zf:
            # Files to backup
            files_to_backup = ['config.json', 'threat_feed.db', 'safe_list.txt', 'jobs.sqlite']

            for filename in files_to_backup:
                file_path = os.path.join(DATA_DIR, filename)
                if os.path.exists(file_path):
                    zf.write(file_path, filename)

        memory_file.seek(0)
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        return send_file(
            memory_file,
            mimetype='application/zip',
            as_attachment=True,
            download_name=f'threat_feed_backup_{timestamp}.zip'
        )
    except Exception as e:
        return api_error(str(e), "BACKUP_ERROR", 500)


@bp_api.route('/restore', methods=['POST'])
@login_required
def restore_system():
    if 'backup_file' not in request.files:
        flash('No file part', 'danger')
        return redirect(url_for('dashboard.index'))

    file = request.files['backup_file']
    if file.filename == '':
        flash('No selected file', 'danger')
        return redirect(url_for('dashboard.index'))

    if file and file.filename.endswith('.zip'):
        try:
            with zipfile.ZipFile(file) as zf:
                valid_files = ['config.json', 'threat_feed.db', 'safe_list.txt', 'jobs.sqlite']
                file_names = zf.namelist()
                for name in file_names:
                    if name not in valid_files or '..' in name or name.startswith('/'):
                        raise ValueError(f"Invalid file in archive: {name}")
                zf.extractall(DATA_DIR)

            flash('System restored successfully. Configuration reloaded.', 'success')

            # Trigger config reload in main app logic if possible
            # Ideally we expose update_scheduled_jobs in a shared way
            # For now, simplistic reload
            update_scheduled_jobs()

            return redirect(url_for('dashboard.index'))

        except Exception as e:
            flash(f'Error restoring backup: {str(e)}', 'danger')
            return redirect(url_for('dashboard.index'))
    else:
        flash('Invalid file format. Please upload a .zip file.', 'danger')
        return redirect(url_for('dashboard.index'))


@bp_api.route('/safe_list/add', methods=['POST'])
@login_required
def add_safe_list_item():
    item = request.form.get('item')
    if item:
        is_valid, _ = validate_indicator(item)
        if not is_valid:
            flash(f'Error: "{item}" is not a valid IP, CIDR, or Domain/URL.', 'danger')
            return redirect(url_for('dashboard.index'))

        success, message = add_to_safe_list(item)
        if success:
            flash(f'Added to Safe List: {item}', 'success')
        else:
            flash(f'Error adding to Safe List: {message}', 'danger')
    return redirect(url_for('dashboard.index'))


@bp_api.route('/safe_list/remove', methods=['POST'])
@login_required
def remove_safe_list_item():
    item = request.form.get('item')
    if item:
        success, message = remove_from_safe_list(item)
        if success:
            flash(f'Removed from Safe List: {item}', 'success')
        else:
            flash(f'Error removing from Safe List: {message}', 'danger')
    return redirect(url_for('dashboard.index'))


@bp_api.route('/test_feed', methods=['POST'])
@login_required
def api_test_feed():
    try:
        data = request.get_json()
        if not data:
            return api_error("No data provided", "VALIDATION_ERROR", 400)

        name = data.get('name', 'Test')
        url = data.get('url')
        data_format = data.get('format', 'text')
        key_or_column = data.get('key_or_column')

        source_config = {
            "name": name,
            "url": url,
            "format": data_format,
            "key_or_column": key_or_column
        }

        success, message, sample = test_feed_source(source_config)

        if success:
            return api_response({"sample": sample}, message=message)
        else:
            return api_error(message, "FEED_TEST_FAILED", 400)
    except Exception as e:
        return api_error(str(e), "FEED_TEST_ERROR", 500)


# --- SOAR Integration Endpoints ---


@bp_api.route('/indicators', methods=['POST'])
@api_key_required
def add_indicator():
    """
    Add an indicator via API (SOAR).
    Payload:
    {
        "type": "whitelist" | "blacklist",
        "value": "1.2.3.4",
        "comment": "Optional comment",
        "item_type": "ip" | "domain" | "url" (optional, default ip)
    }
    """
    try:
        data = request.get_json()
        if not data:
            return api_error("No data provided", "VALIDATION_ERROR", 400)

        action_type = data.get('type')  # whitelist or blacklist
        value = data.get('value')
        comment = data.get('comment', 'Added via API')
        item_type = data.get('item_type', 'ip')

        if not value or not action_type:
            return api_error("Missing value or type", "VALIDATION_ERROR", 400)

        # Validation
        is_valid, _ = validate_indicator(value)
        if not is_valid:
            return api_error(f'"{value}" is not a valid IP, CIDR, or Domain/URL', "VALIDATION_ERROR", 400)

        if action_type.lower() == 'whitelist':
            success, msg = add_whitelist_item(value, item_type=item_type, description=comment)

        elif action_type.lower() == 'blacklist':
            success, msg = add_api_blacklist_item(value, item_type=item_type, comment=comment)
            if success:
                trigger_background_regeneration()
        else:
            return api_error("Invalid type. Use whitelist or blacklist", "VALIDATION_ERROR", 400)

        if success:
            return api_response({"value": value, "type": action_type}, message=msg)
        else:
            return api_error(msg, "INDICATOR_ADD_FAILED", 400)

    except Exception as e:
        logger.error(f"API Error adding indicator: {e}")
        return api_error(str(e), "INDICATOR_ADD_ERROR", 500)


def _handle_api_indicator_removal(value, type_hint):
    """Helper to perform the actual removal from DB."""
    deleted = False
    msgs = []

    # Try Blacklist
    if not type_hint or type_hint == 'blacklist':
        if remove_api_blacklist_item(value):
            deleted = True
            msgs.append("Removed from Blacklist")

    # Try Whitelist
    if not type_hint or type_hint == 'whitelist':
        w_list = get_whitelist()
        found_id = next((item['id'] for item in w_list if item['item'] == value), None)

        if found_id and remove_whitelist_item(found_id):
            deleted = True
            msgs.append("Removed from Whitelist")

    return deleted, msgs


@bp_api.route('/indicators', methods=['DELETE'])
@api_key_required
def remove_indicator():
    """
    Remove an indicator via API.
    """
    try:
        data = request.get_json()
        if not data or not data.get('value'):
            return api_error("Missing value", "VALIDATION_ERROR", 400)

        value = data.get('value')
        type_hint = data.get('type')

        deleted, msgs = _handle_api_indicator_removal(value, type_hint)

        if deleted:
            trigger_background_regeneration()
            return api_response({"value": value}, message=", ".join(msgs))

        return api_error("Item not found", "NOT_FOUND", 404)

    except Exception as e:
        logger.error(f"API Error removing indicator: {e}")
        return api_error(str(e), "INDICATOR_REMOVE_ERROR", 500)


from .auth import api_key_required

# --- FortiDeceptor Integration ---

@bp_api.route('/deceptor/block', methods=['POST'])
@api_key_required
def deceptor_block():
    """
    FortiDeceptor integration for blocking multiple IPs.
    """
    logger.info(f"CRITICAL: Deceptor Block Function reached! Client IP: {request.remote_addr}")
    try:
        # 1. Capture Raw Data for Debugging
        client_ip = request.remote_addr
        raw_headers = _sanitize_headers_for_log(request.headers)
        raw_body = request.get_data(as_text=True)
        data_all = request.get_json(silent=True) or request.form
        
        logger.info(f"Deceptor Request Details | Headers: {raw_headers} | Body: {raw_body}")
        
        # 2. Extract IP(s) from various locations - Prioritize Body for actual data
        input_data = data_all.get('whblockdata') or data_all.get('whblockheader') or data_all.get('Hacker-IP')
        
        # Fallback to headers if body is empty
        if not input_data:
            input_data = request.headers.get('whblockheader') or request.headers.get('Hacker-IP')
            
        if not input_data:
            # Fallback regex scan in body
            import re
            ip_matches = re.findall(r'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})', raw_body)
            if ip_matches:
                input_data = ",".join(ip_matches)

        if not input_data:
            logger.error(f"Deceptor BLOCK Failed: No IP found. Body: {raw_body}")
            return jsonify({'status': 'error', 'message': 'No IP found'}), 400

        # 3. Process Multiple IPs (Split by comma or space)
        import re
        # Normalize delimiters to comma
        normalized_ips = re.sub(r'[\s,;]+', ',', input_data).strip(',')
        ip_list = [ip.strip() for ip in normalized_ips.split(',') if ip.strip()]

        config = read_config()
        default_lifetime_days = config.get("indicator_lifetime_days", 30)

        expiry_input = data_all.get('expiry')
        if expiry_input:
            try:
                seconds = int(expiry_input)
                expires_at = (datetime.now(UTC) + timedelta(seconds=seconds)).isoformat()
                expiry_desc = f"{seconds}s"
            except Exception:
                expires_at = (datetime.now(UTC) + timedelta(days=default_lifetime_days)).isoformat()
                expiry_desc = f"{default_lifetime_days} days (system default)"
        else:
            expires_at = (datetime.now(UTC) + timedelta(days=default_lifetime_days)).isoformat()
            expiry_desc = f"{default_lifetime_days} days (system default)"

        comment = f"FortiDeceptor block (Expiry: {expiry_desc})"
        
        added_count = 0
        successful_indicators = []
        from ..utils import validate_indicator
        
        for ip in ip_list:
            # Handle Test Strings & Probes
            if ip.lower() in _DECEPTOR_PROBE_STRINGS:
                logger.info(f"Deceptor probe/test string detected: {ip}")
                continue

            is_valid, _ = validate_indicator(ip)
            if is_valid:
                success, _ = add_api_blacklist_item(ip, item_type='ip', comment=comment, expires_at=expires_at, source="FortiDeceptor")
                if success:
                    added_count += 1
                    successful_indicators.append((ip, 'Unknown', 'ip'))
            else:
                logger.warning(f"Skipping invalid IP from Deceptor: {ip}")

        if successful_indicators:
            # Bulk upsert once to reduce DB transaction overhead for multi-IP payloads.
            try:
                upsert_indicators_bulk(successful_indicators, source_name="FortiDeceptor")
            except Exception as db_err:
                logger.error(f"Failed to upsert Deceptor indicators to main DB: {db_err}")

        # ALWAYS return success 200 if the request reached here with valid API Key
        # This prevents Deceptor from showing "Failed" status during probes
        # trigger_background_regeneration() <-- DEACTIVATED to prevent GUI freezing
        return jsonify({'status': 'success', 'message': f'Processed {added_count} indicators.'}), 200

    except Exception as e:
        logger.error(f"FortiDeceptor API Error: {e}")
        return jsonify({'status': 'error', 'message': str(e)}), 500


@bp_api.route('/deceptor/unblock', methods=['POST'])
@api_key_required
def deceptor_unblock():
    """
    FortiDeceptor integration for unblocking IPs.
    Extracts IP from 'whunblockheader' or 'whunblockdata'.
    """
    try:
        # 1. Extract IP
        ip = request.headers.get('whunblockheader')
        if not ip:
            data = request.get_json(silent=True) or request.form
            ip = data.get('whunblockdata')

        if not ip:
            return jsonify({'status': 'error', 'message': 'Missing IP (Hacker-IP)'}), 400

        # 2. Remove from API Blacklist
        if remove_api_blacklist_item(ip):
            # trigger_background_regeneration() <-- DEACTIVATED to prevent GUI freezing
            return jsonify({'status': 'success', 'message': f"IP {ip} removed from blacklist."})

        return jsonify({'status': 'error', 'message': 'Item not found in blacklist'}), 404

    except Exception as e:
        logger.error(f"FortiDeceptor API Error: {e}")
        return jsonify({'status': 'error', 'message': str(e)}), 500
