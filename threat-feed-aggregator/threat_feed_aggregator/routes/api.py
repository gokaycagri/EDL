from flask import jsonify, request, send_file, flash, redirect, url_for
from datetime import datetime
from tzlocal import get_localzone
import io
import os
import zipfile
import threading
import logging

from ..config_manager import DATA_DIR, read_config
from ..aggregator import CURRENT_JOB_STATUS, regenerate_edl_files, test_feed_source, run_aggregator
from ..microsoft_services import process_microsoft_feeds
from ..github_services import process_github_feeds
from ..azure_services import process_azure_feeds
from ..db_manager import (
    get_historical_stats, 
    get_job_history, 
    clear_job_history, 
    add_api_blacklist_item, 
    remove_api_blacklist_item,
    add_whitelist_item,
    remove_whitelist_item,
    get_whitelist,
    get_api_blacklist_items
)
from ..log_manager import get_live_logs
from ..utils import add_to_safe_list, remove_from_safe_list

from . import bp_api
from .auth import login_required, api_key_required

logger = logging.getLogger(__name__)

# Global aggregation status (moved from app.py)
AGGREGATION_STATUS = "idle"

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
    
    if update_status:
        AGGREGATION_STATUS = "completed"
    logging.debug("aggregation_task completed.")

@bp_api.route('/run')
@login_required
def run_script():
    logging.debug("Received request to /api/run endpoint.")
    global AGGREGATION_STATUS
    if AGGREGATION_STATUS == "running":
        logging.info("Aggregation already running, returning status.")
        return jsonify({"status": AGGREGATION_STATUS})
    
    AGGREGATION_STATUS = "running"
    thread = threading.Thread(target=aggregation_task)
    thread.start()
    logging.info("Aggregation task started in a new thread.")
    return jsonify({"status": "running"})

@bp_api.route('/status')
@login_required
def status():
    # Note: Client JS expects /status, currently this is /api/status due to url_prefix
    # We might need to adjust JS or register this route specifically at root if needed.
    # For now keeping it here.
    logging.debug("Received request to /api/status endpoint.")
    return jsonify({"status": AGGREGATION_STATUS})

@bp_api.route('/status_detailed')
@login_required
def status_detailed():
    """Returns detailed status of currently running jobs."""
    return jsonify(CURRENT_JOB_STATUS)

@bp_api.route('/trend_data')
@login_required
def trend_data():
    """Returns historical stats for the chart."""
    days = request.args.get('days', default=30, type=int)
    data = get_historical_stats(days)
    
    # Format dates for Chart.js
    local_tz = get_localzone()
    formatted_data = []
    for row in data:
        try:
            dt = datetime.fromisoformat(row['timestamp'])
            row['timestamp'] = dt.astimezone(local_tz).strftime('%Y-%m-%d %H:%M')
            formatted_data.append(row)
        except:
            pass
            
    return jsonify(formatted_data)

@bp_api.route('/history')
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

@bp_api.route('/history/clear', methods=['POST'])
@login_required
def clear_history_route():
    """Clears the job history."""
    if clear_job_history():
        return jsonify({'status': 'success', 'message': 'Job history cleared.'})
    else:
        return jsonify({'status': 'error', 'message': 'Failed to clear job history.'}), 500

@bp_api.route('/live_logs')
@login_required
def live_logs():
    """Returns the latest logs from memory."""
    return jsonify(get_live_logs())

@bp_api.route('/source_stats')
@login_required
def source_stats_api():
    """Returns current counts and last updated times for all sources."""
    from ..config_manager import read_stats
    from tzlocal import get_localzone
    
    stats = read_stats()
    local_tz = get_localzone()
    
    formatted_stats = {}
    for name, data in stats.items():
        if isinstance(data, dict) and 'last_updated' in data:
            try:
                dt = datetime.fromisoformat(data['last_updated'])
                formatted_stats[name] = {
                    "count": data.get('count', 0),
                    "last_updated": dt.astimezone(local_tz).strftime('%d/%m/%Y %H:%M')
                }
            except:
                formatted_stats[name] = data
        else:
            formatted_stats[name] = data
            
    return jsonify(formatted_stats)

@bp_api.route('/regenerate_lists', methods=['POST'])
@login_required
def api_regenerate_lists():
    success, msg = regenerate_edl_files()
    if success:
        return jsonify({'status': 'success', 'message': msg})
    else:
        return jsonify({'status': 'error', 'message': msg})

@bp_api.route('/update_ms365', methods=['POST'])
@login_required
def api_update_ms365():
    try:
        success, msg = process_microsoft_feeds()
        if success:
            return jsonify({'status': 'success', 'message': msg})
        else:
            return jsonify({'status': 'error', 'message': msg})
    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)})

@bp_api.route('/update_github', methods=['POST'])
@login_required
def api_update_github():
    try:
        success, msg = process_github_feeds()
        if success:
            return jsonify({'status': 'success', 'message': msg})
        else:
            return jsonify({'status': 'error', 'message': msg})
    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)})

@bp_api.route('/update_azure', methods=['POST'])
@login_required
def api_update_azure():
    try:
        success, msg = process_azure_feeds()
        if success:
            return jsonify({'status': 'success', 'message': msg})
        else:
            return jsonify({'status': 'error', 'message': msg})
    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)})

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
        return jsonify({'status': 'error', 'message': str(e)}), 500

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
            from ..app import update_scheduled_jobs
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
        from ..utils import validate_indicator
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
            return jsonify({'status': 'error', 'message': 'No data provided'})
        
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
        
        return jsonify({
            'status': 'success' if success else 'error',
            'message': message,
            'sample': sample
        })
    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)})

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
            return jsonify({'status': 'error', 'message': 'No data provided'}), 400
        
        action_type = data.get('type') # whitelist or blacklist
        value = data.get('value')
        comment = data.get('comment', 'Added via API')
        item_type = data.get('item_type', 'ip')
        
        if not value or not action_type:
            return jsonify({'status': 'error', 'message': 'Missing value or type'}), 400
            
        # Validation
        from ..utils import validate_indicator
        is_valid, _ = validate_indicator(value)
        if not is_valid:
            return jsonify({'status': 'error', 'message': f'"{value}" is not a valid IP, CIDR, or Domain/URL'}), 400

        if action_type.lower() == 'whitelist':
            # Whitelist Logic
            success, msg = add_whitelist_item(value, description=comment)
        
        elif action_type.lower() == 'blacklist':
            # Blacklist Logic
            success, msg = add_api_blacklist_item(value, item_type=item_type, comment=comment)
            # Trigger immediate background regeneration if needed? 
            # Ideally we should, but for performance maybe just let it be picked up on next run 
            # or we can force a quick update of the files.
            if success:
                # Regenerate files to reflect changes immediately
                # Note: This doesn't run the full fetch, just DB -> File generation
                try:
                    regenerate_edl_files()
                except:
                    pass
        else:
            return jsonify({'status': 'error', 'message': 'Invalid type. Use whitelist or blacklist'}), 400
            
        if success:
            return jsonify({'status': 'success', 'message': msg})
        else:
            return jsonify({'status': 'error', 'message': msg}), 400
            
    except Exception as e:
        logger.error(f"API Error adding indicator: {e}")
        return jsonify({'status': 'error', 'message': str(e)}), 500

@bp_api.route('/indicators', methods=['DELETE'])
@api_key_required
def remove_indicator():
    """
    Remove an indicator via API.
    Payload:
    {
        "value": "1.2.3.4",
        "type": "whitelist" | "blacklist" (optional hint, otherwise tries both)
    }
    """
    try:
        data = request.get_json()
        if not data:
            return jsonify({'status': 'error', 'message': 'No data provided'}), 400
            
        value = data.get('value')
        type_hint = data.get('type')
        
        if not value:
             return jsonify({'status': 'error', 'message': 'Missing value'}), 400
        
        deleted = False
        msgs = []
        
        # Try Blacklist
        if not type_hint or type_hint == 'blacklist':
            if remove_api_blacklist_item(value):
                deleted = True
                msgs.append("Removed from Blacklist")
        
        # Try Whitelist
        if not type_hint or type_hint == 'whitelist':
            # Whitelist removal by value requires finding ID first or modifying DB function
            # Since our DB function `remove_whitelist_item` takes ID, let's look it up.
            w_list = get_whitelist()
            found_id = None
            for item in w_list:
                if item['item'] == value:
                    found_id = item['id']
                    break
            
            if found_id:
                if remove_whitelist_item(found_id):
                    deleted = True
                    msgs.append("Removed from Whitelist")
        
        if deleted:
            # Regenerate files
            try:
                regenerate_edl_files()
            except:
                pass
            return jsonify({'status': 'success', 'message': ", ".join(msgs)})
        else:
            return jsonify({'status': 'error', 'message': 'Item not found'}), 404

    except Exception as e:
        logger.error(f"API Error removing indicator: {e}")
        return jsonify({'status': 'error', 'message': str(e)}), 500
