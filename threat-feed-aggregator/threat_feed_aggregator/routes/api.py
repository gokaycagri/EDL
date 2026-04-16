import csv
from datetime import UTC, datetime, timedelta
import io
import json
import logging
import os
import threading
import time
import zipfile

from flask import Response, flash, jsonify, redirect, request, send_file, session, stream_with_context, url_for
import pytz

from ..aggregator import fetch_and_process_single_feed, regenerate_edl_files, run_aggregator, test_feed_source
from ..api_spec import OPENAPI_SPEC
from ..auth_manager import permission_required
from ..azure_services import process_azure_feeds
from ..config_manager import DATA_DIR, read_config, read_stats
from ..db_manager import (
    add_api_blacklist_item,
    add_whitelist_item,
    clear_job_history,
    get_api_blacklist_items,
    get_custom_list_by_token,
    get_custom_list_count,
    get_filtered_indicators_iter,
    get_historical_stats,
    get_indicator_counts_by_type,
    get_job_history,
    get_unique_indicator_count,
    get_whitelist,
    remove_api_blacklist_item,
    remove_whitelist_item,
    upsert_indicators_bulk,
)
from ..github_services import process_github_feeds
from ..log_manager import clear_logs, get_live_logs
from ..microsoft_services import process_microsoft_feeds
from ..response_helpers import api_error, api_response
from ..scheduler_manager import scheduler, update_scheduled_jobs
from ..services.job_service import job_service
from ..utils import add_to_safe_list, format_timestamp, remove_from_safe_list, validate_indicator
from . import bp_api
from .auth import api_key_required, login_required

logger = logging.getLogger(__name__)

_DECEPTOR_PROBE_STRINGS = {"hacker-ip", "1", "test", "ping"}


@bp_api.route("/docs")
def api_docs():
    """Serve OpenAPI 3.1 specification as JSON."""
    return jsonify(OPENAPI_SPEC)


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


CACHE_DIR = os.path.join(DATA_DIR, "edl_cache")
try:
    os.makedirs(CACHE_DIR, exist_ok=True)
except OSError:
    logger.warning(f"Could not create EDL cache directory: {CACHE_DIR}")


def _get_cached_edl_path(token, fmt):
    # Sanitize token to prevent path traversal — allow only alphanumeric, hyphen, underscore
    safe_token = "".join(c for c in token if c.isalnum() or c in "-_")
    if not safe_token:
        raise ValueError("Invalid token")
    safe_fmt = "".join(c for c in fmt if c.isalnum())
    result = os.path.join(CACHE_DIR, f"{safe_token}.{safe_fmt}")
    # Belt-and-suspenders: ensure resolved path stays inside CACHE_DIR
    if not os.path.realpath(result).startswith(os.path.realpath(CACHE_DIR)):
        raise ValueError("Path traversal detected")
    return result


def _is_cache_valid(path, ttl_seconds=600):
    if not os.path.exists(path):
        return False
    # If file exists but is empty, treat as invalid — force regeneration
    if os.path.getsize(path) == 0:
        logger.debug(f"Cache file {path} is empty — invalidating.")
        return False
    mtime = os.stat(path).st_mtime
    age = time.time() - mtime
    return age < ttl_seconds


@bp_api.route("/edl/firewall/<path:filename>", methods=["GET", "HEAD"])
def get_firewall_edl(filename):
    """
    Public-ish endpoint for firewalls to fetch EDL files.
    Does NOT require session login.
    """
    from flask import make_response, send_from_directory

    # Security: Ensure we only serve .txt files (no path traversal)
    safe_filename = os.path.basename(filename)
    if not safe_filename.endswith(".txt"):
        return jsonify({"error": "Invalid file type"}), 403

    from ..config_manager import DATA_DIR

    file_path = os.path.join(DATA_DIR, safe_filename)
    # Verify resolved path stays inside DATA_DIR to prevent path traversal
    if not os.path.realpath(file_path).startswith(os.path.realpath(DATA_DIR)):
        return jsonify({"error": "Invalid path"}), 403
    logger.info(f"Firewall EDL request: {safe_filename} from {request.remote_addr} (Method: {request.method})")

    if not os.path.exists(file_path):
        logger.error(f"Firewall EDL File NOT FOUND: {file_path}")
        return jsonify({"error": "File not found"}), 404

    # Handle HEAD request for connector validation
    if request.method == "HEAD":
        response = make_response("", 200)
        response.headers["Content-Type"] = "text/plain"
        response.headers["Content-Length"] = os.path.getsize(file_path)
        return response

    response = make_response(send_from_directory(DATA_DIR, safe_filename, mimetype="text/plain"))
    # Display inline in browser (not download) — firewalls read body regardless
    response.headers["Content-Disposition"] = "inline"
    # Disable caching to ensure firewalls get fresh data
    response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
    response.headers["Pragma"] = "no-cache"
    response.headers["Expires"] = "0"
    return response


@bp_api.route("/custom_list/count/<int:list_id>")
@login_required
def custom_list_count_api(list_id):
    """Returns the item count for a custom list."""
    count = get_custom_list_count(list_id)
    return api_response({"count": count})


@bp_api.route("/edl/custom/<token>")
def get_saved_custom_edl(token):
    """
    Returns a saved custom EDL by its token.
    Uses file-based caching (10 mins) and streaming for performance.
    """
    list_config = get_custom_list_by_token(token)
    if not list_config:
        return jsonify({"error": "List not found"}), 404

    output_format = list_config["format"]
    cache_path = _get_cached_edl_path(token, output_format)

    # 1. Serve from Cache if valid
    if _is_cache_valid(cache_path):
        if output_format == "text":
            mimetype = "text/plain"
        elif output_format == "json":
            mimetype = "application/json"
        else:
            mimetype = "text/csv"
        resp = send_file(cache_path, mimetype=mimetype, conditional=False)
        resp.headers["Content-Disposition"] = "inline"
        resp.headers["Cache-Control"] = "no-store, no-cache, must-revalidate"
        resp.headers["Pragma"] = "no-cache"
        resp.headers["Expires"] = "0"
        return resp

    # 2. Regenerate Cache (Streaming)
    include_sources = list_config["sources"]
    include_types = list_config["types"]
    include_types_filter = _build_type_filter(include_types)

    try:
        iterator = get_filtered_indicators_iter(include_sources)

        # Write to unique temporary file then rename (atomic, concurrent-safe)
        import uuid

        temp_path = cache_path + f".{uuid.uuid4().hex}.tmp"

        with open(temp_path, "w", encoding="utf-8") as f:
            if output_format == "text":
                # Optimized Stream for Text
                count = 0
                for row in iterator:
                    if not include_types_filter or row["type"] in include_types_filter:
                        f.write(row["indicator"] + "\n")
                        count += 1
                if count == 0:
                    logger.warning(f"Custom EDL ({token}) generated 0 records.")
            else:
                # Fallback for CSV/JSON (requires list structure usually)
                # But we can optimize CSV streaming
                if output_format == "csv":
                    import csv

                    writer = csv.writer(f)
                    writer.writerow(["indicator", "type", "risk_score", "country"])
                    for row in iterator:
                        if not include_types_filter or row["type"] in include_types_filter:
                            writer.writerow([row["indicator"], row["type"], row["risk_score"], row["country"]])
                elif output_format == "json":
                    # Write JSON incrementally to avoid holding large lists in memory.
                    first_item = True
                    f.write("[")
                    for row in iterator:
                        if not include_types_filter or row["type"] in include_types_filter:
                            if not first_item:
                                f.write(",\n")
                            f.write(
                                json.dumps(
                                    {
                                        "indicator": row["indicator"],
                                        "type": row["type"],
                                        "risk_score": row["risk_score"],
                                        "country": row["country"],
                                    }
                                )
                            )
                            first_item = False
                    f.write("]")

        # Atomically replace cache file
        os.replace(temp_path, cache_path)

        if output_format == "text":
            mimetype = "text/plain"
        elif output_format == "json":
            mimetype = "application/json"
        else:
            mimetype = "text/csv"
        resp = send_file(cache_path, mimetype=mimetype, conditional=False)
        resp.headers["Content-Disposition"] = "inline"
        resp.headers["Cache-Control"] = "no-store, no-cache, must-revalidate"
        resp.headers["Pragma"] = "no-cache"
        resp.headers["Expires"] = "0"
        return resp

    except Exception as e:
        logger.error(f"Error generating Custom EDL {token}: {e}")
        # Clean up temp file on error
        try:
            if os.path.exists(temp_path):
                os.unlink(temp_path)
        except OSError:
            pass
        return jsonify({"error": "Generation failed"}), 500


@bp_api.route("/edl/generic")
@api_key_required
def get_generic_edl():
    """
    Returns a generic EDL.
    Params:
    - types: comma separated (ip,domain,url,cidr)
    - format: text, csv, json
    - delimiter: for text format (default newline)
    """
    types_str = request.args.get("types")
    include_types = types_str.split(",") if types_str else None

    sources_str = request.args.get("sources")
    include_sources = sources_str.split(",") if sources_str and sources_str.strip() else None

    output_format = request.args.get("format", "text")
    delimiter = request.args.get("delimiter", "\n")
    include_types_filter = _build_type_filter(include_types)

    # Validation
    if output_format not in ["text", "csv", "json"]:
        return jsonify({"error": "Invalid format"}), 400

    iterator = get_filtered_indicators_iter(include_sources)

    if output_format == "text":

        @stream_with_context
        def generate_text():
            first_item = True
            for row in iterator:
                if include_types_filter and row["type"] not in include_types_filter:
                    continue
                if not first_item:
                    yield delimiter
                yield row["indicator"]
                first_item = False

        return Response(generate_text(), mimetype="text/plain")

    if output_format == "csv":

        @stream_with_context
        def generate_csv():
            yield _csv_row(["indicator", "type", "risk_score", "country"])
            for row in iterator:
                if include_types_filter and row["type"] not in include_types_filter:
                    continue
                yield _csv_row([row["indicator"], row["type"], row["risk_score"], row["country"]])

        return Response(generate_csv(), mimetype="text/csv")

    @stream_with_context
    def generate_json():
        first_item = True
        yield "["
        for row in iterator:
            if include_types_filter and row["type"] not in include_types_filter:
                continue
            if not first_item:
                yield ","
            yield json.dumps(
                {
                    "indicator": row["indicator"],
                    "type": row["type"],
                    "risk_score": row["risk_score"],
                    "country": row["country"],
                }
            )
            first_item = False
        yield "]"

    return Response(generate_json(), mimetype="application/json")


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


_aggregation_lock = threading.Lock()


@bp_api.route("/run", methods=["POST"])
@login_required
def run_script():
    logging.debug("Received request to /api/run endpoint.")
    if not _aggregation_lock.acquire(blocking=False):
        logging.info("Aggregation already running, returning status.")
        return api_response({"aggregation_status": "running"}, message="Aggregation already running")

    def _run():
        try:
            aggregation_task()
        finally:
            _aggregation_lock.release()

    thread = threading.Thread(target=_run)
    thread.start()
    logging.info("Aggregation task started in a new thread.")
    return api_response({"aggregation_status": "running"}, message="Aggregation started")


@bp_api.route("/run_single/<path:name>", methods=["POST"])
@login_required
def run_single_feed(name):
    """Triggers a single feed update in the background."""
    config = read_config()
    source = next((s for s in config.get("source_urls", []) if s["name"] == name), None)

    if not source:
        return api_error("Source not found", "SOURCE_NOT_FOUND", 404)

    thread = threading.Thread(target=fetch_and_process_single_feed, args=(source,))
    thread.start()

    return api_response({"source": name, "aggregation_status": "running"}, message=f"Fetch started for {name}")


@bp_api.route("/status")
@login_required
def status():
    logging.debug("Received request to /api/status endpoint.")
    return api_response({"aggregation_status": job_service.aggregation_status})


@bp_api.route("/status_detailed")
@login_required
def status_detailed():
    """Returns detailed status of currently running jobs."""
    return api_response(job_service.get_all_job_statuses())


@bp_api.route("/scheduled_jobs")
@login_required
def get_scheduled_jobs():
    """Returns sorted list of upcoming scheduled jobs."""
    config = read_config()
    target_tz = pytz.timezone(config.get("timezone", "UTC"))

    jobs = scheduler.get_jobs()
    formatted_jobs = []

    for job in jobs:
        # Safely get next_run_time as it might not exist yet if job is being scheduled
        jt = getattr(job, "next_run_time", None)
        next_run = jt.astimezone(target_tz) if jt else None
        time_until = "N/A"
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

        formatted_jobs.append(
            {
                "name": job.name,
                "next_run_time": next_run.strftime("%d/%m/%Y %H:%M") if next_run else "N/A",
                "next_run_timestamp": next_run.timestamp() if next_run else 0,
                "time_until": time_until,
            }
        )

    # Sort by nearest run time
    formatted_jobs.sort(key=lambda x: x["next_run_timestamp"] if x["next_run_timestamp"] > 0 else float("inf"))

    return api_response({"items": formatted_jobs, "total": len(formatted_jobs)})


@bp_api.route("/trend_data")
@login_required
def trend_data():
    """Returns historical stats for the chart."""
    days = request.args.get("days", default=30, type=int)
    data = get_historical_stats(days)

    # Format dates for Chart.js using configured TZ
    formatted_data = []
    for row in data:
        try:
            row["timestamp"] = format_timestamp(row["timestamp"], fmt="%Y-%m-%d %H:%M")
            formatted_data.append(row)
        except Exception:
            pass

    return api_response({"items": formatted_data, "total": len(formatted_data)})


@bp_api.route("/history")
@login_required
def job_history():
    """Returns past job execution history."""
    limit = request.args.get("limit", default=20, type=int)
    history = get_job_history(limit=limit)
    # Format dates
    for item in history:
        try:
            # We need raw datetime objects for duration calculation before formatting
            start_dt = datetime.fromisoformat(item["start_time"])

            if item["end_time"]:
                end_dt = datetime.fromisoformat(item["end_time"])
                duration = (end_dt - start_dt).total_seconds()
                item["duration"] = f"{duration:.2f}s"
                item["end_time"] = format_timestamp(item["end_time"], fmt="%H:%M:%S")
            else:
                item["duration"] = "Running..."

            item["start_time"] = format_timestamp(item["start_time"], fmt="%Y-%m-%d %H:%M:%S")
        except Exception:
            pass
    return api_response({"items": history, "total": len(history)})


@bp_api.route("/history/clear", methods=["POST"])
@login_required
def clear_history_route():
    """Clears the job history."""
    logger.info("RECEIVED request to clear job history")
    if clear_job_history():
        return api_response(message="Job history cleared.")
    else:
        logger.error("Failed to clear job history in DB")
        return api_error("Failed to clear job history.", "DB_ERROR", 500)


@bp_api.route("/live_logs")
@login_required
def live_logs():
    """Returns the latest logs from memory."""
    logs = get_live_logs()
    return api_response({"items": logs, "total": len(logs)})


@bp_api.route("/live_logs/clear", methods=["POST"])
@login_required
def clear_live_logs_route():
    """Clears the live logs from memory."""
    clear_logs()
    return api_response(message="Live logs cleared.")


@bp_api.route("/feed_health")
@login_required
def feed_health_api():
    """Returns health status for all feeds."""
    from ..services.feed_health import get_all_health_statuses

    return api_response(get_all_health_statuses())


@bp_api.route("/active_sources")
@login_required
def active_sources_api():
    """Returns distinct source names that have actual data in the indicator_sources table.
    Used for populating custom EDL source selection — guarantees only valid source names are shown."""
    from ..database.connection import db_readonly

    try:
        with db_readonly() as db:
            cursor = db.execute(
                "SELECT source_name, COUNT(DISTINCT indicator) as count "
                "FROM indicator_sources GROUP BY source_name ORDER BY source_name"
            )
            sources = [{"name": row["source_name"], "count": row["count"]} for row in cursor.fetchall()]
        return api_response({"sources": sources})
    except Exception as e:
        logger.error(f"active_sources_api error: {e}")
        return api_error("Failed to fetch active sources", 500)


@bp_api.route("/source_stats")
@login_required
def source_stats_api():
    """Returns current counts and last updated times for all sources."""
    from ..config_manager import read_config
    from ..db_manager import get_country_stats, get_latest_job_times, get_source_counts

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
        if name == "last_updated":
            formatted_stats[name] = format_timestamp(data)
            continue

        if isinstance(data, dict):
            # Use DB count if available, otherwise fallback to stats file
            current_count = real_db_counts.get(name, data.get("count", 0))

            # Use DB timestamp if available, otherwise fallback
            last_ts = real_db_times.get(name, data.get("last_updated"))

            formatted_stats[name] = {"count": current_count, "last_updated": format_timestamp(last_ts)}
        else:
            formatted_stats[name] = data

    # 2. Ensure sources in DB (but maybe missing in stats.json) are included if they match config
    configured_sources = [s["name"] for s in config.get("source_urls", [])]

    # Merge keys from both DB counts and DB times to catch all active sources
    all_known_sources = set(real_db_counts.keys()) | set(real_db_times.keys())

    for name in all_known_sources:
        if name in configured_sources and name not in formatted_stats:
            formatted_stats[name] = {
                "count": real_db_counts.get(name, 0),
                "last_updated": format_timestamp(real_db_times.get(name)),
            }

    return api_response(
        {
            "sources": formatted_stats,
            "totals": {
                "total": total_count,
                "ip": counts_by_type.get("ip", 0) + counts_by_type.get("cidr", 0),
                "domain": counts_by_type.get("domain", 0) + counts_by_type.get("url", 0),
                "feeds": len(config.get("source_urls", [])),
            },
            "country_stats": country_stats,
        }
    )


@bp_api.route("/regenerate_lists", methods=["POST"])
@login_required
def api_regenerate_lists():
    success, msg = regenerate_edl_files()
    if success:
        return api_response(message=msg)
    else:
        return api_error(msg, "REGENERATION_FAILED", 500)


@bp_api.route("/update_ms365", methods=["POST"])
@login_required
def api_update_ms365():
    try:
        success, msg = process_microsoft_feeds()
        if success:
            return api_response(message=msg)
        else:
            return api_error(msg, "MS365_UPDATE_FAILED", 500)
    except Exception as e:
        logger.error(f"MS365 update error: {e}", exc_info=True)
        return api_error("Failed to update MS365 feeds", "MS365_UPDATE_ERROR", 500)


@bp_api.route("/update_github", methods=["POST"])
@login_required
def api_update_github():
    try:
        success, msg = process_github_feeds()
        if success:
            return api_response(message=msg)
        else:
            return api_error(msg, "GITHUB_UPDATE_FAILED", 500)
    except Exception as e:
        logger.error(f"GitHub update error: {e}", exc_info=True)
        return api_error("Failed to update GitHub feeds", "GITHUB_UPDATE_ERROR", 500)


@bp_api.route("/update_azure", methods=["POST"])
@login_required
def api_update_azure():
    try:
        success, msg = process_azure_feeds()
        if success:
            return api_response(message=msg)
        else:
            return api_error(msg, "AZURE_UPDATE_FAILED", 500)
    except Exception as e:
        logger.error(f"Azure update error: {e}", exc_info=True)
        return api_error("Failed to update Azure feeds", "AZURE_UPDATE_ERROR", 500)


@bp_api.route("/backup", methods=["POST"])
@login_required
@permission_required("system", "rw")
def backup_system():
    try:
        from ..services.audit_service import log_action

        username = session.get("username", "unknown")
        log_action(
            username,
            "backup_download",
            ip_address=request.remote_addr,
            details=f"User: {username}",
        )

        memory_file = io.BytesIO()
        with zipfile.ZipFile(memory_file, "w", zipfile.ZIP_DEFLATED) as zf:
            files_to_backup = ["config.json", "threat_feed.db", "safe_list.txt", "jobs.sqlite"]
            for filename in files_to_backup:
                file_path = os.path.join(DATA_DIR, filename)
                if os.path.exists(file_path):
                    zf.write(file_path, filename)

        memory_file.seek(0)
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        return send_file(
            memory_file,
            mimetype="application/zip",
            as_attachment=True,
            download_name=f"threat_feed_backup_{timestamp}.zip",
        )
    except Exception as e:
        logger.error(f"Backup error: {e}", exc_info=True)
        return api_error("Failed to create backup", "BACKUP_ERROR", 500)


@bp_api.route("/restore", methods=["POST"])
@login_required
@permission_required("system", "rw")
def restore_system():
    if "backup_file" not in request.files:
        flash("No file part", "danger")
        return redirect(url_for("dashboard.index"))

    file = request.files["backup_file"]
    if file.filename == "":
        flash("No selected file", "danger")
        return redirect(url_for("dashboard.index"))

    if file and file.filename.endswith(".zip"):
        try:
            with zipfile.ZipFile(file) as zf:
                valid_files = ["config.json", "threat_feed.db", "safe_list.txt", "jobs.sqlite"]
                file_names = zf.namelist()
                for name in file_names:
                    if name not in valid_files:
                        raise ValueError(f"Unexpected file in archive: {name}")
                    dest = os.path.realpath(os.path.join(DATA_DIR, name))
                    if not dest.startswith(os.path.realpath(DATA_DIR) + os.sep):
                        raise ValueError(f"Path traversal detected: {name}")
                    with zf.open(name) as src, open(dest, "wb") as dst:
                        dst.write(src.read())

            flash("System restored successfully. Configuration reloaded.", "success")

            # Trigger config reload in main app logic if possible
            # Ideally we expose update_scheduled_jobs in a shared way
            # For now, simplistic reload
            update_scheduled_jobs()

            return redirect(url_for("dashboard.index"))

        except Exception as e:
            logger.error(f"Error restoring backup: {e}", exc_info=True)
            flash("Error restoring backup. Check server logs for details.", "danger")
            return redirect(url_for("dashboard.index"))
    else:
        flash("Invalid file format. Please upload a .zip file.", "danger")
        return redirect(url_for("dashboard.index"))


@bp_api.route("/safe_list/add", methods=["POST"])
@login_required
@permission_required("system", "rw")
def add_safe_list_item():
    item = request.form.get("item")
    if item:
        is_valid, _ = validate_indicator(item)
        if not is_valid:
            flash(f'Error: "{item}" is not a valid IP, CIDR, or Domain/URL.', "danger")
            return redirect(url_for("dashboard.index"))

        success, message = add_to_safe_list(item)
        if success:
            flash(f"Added to Safe List: {item}", "success")
        else:
            flash(f"Error adding to Safe List: {message}", "danger")
    return redirect(url_for("dashboard.index"))


@bp_api.route("/safe_list/remove", methods=["POST"])
@login_required
@permission_required("system", "rw")
def remove_safe_list_item():
    item = request.form.get("item")
    if item:
        success, message = remove_from_safe_list(item)
        if success:
            flash(f"Removed from Safe List: {item}", "success")
        else:
            flash(f"Error removing from Safe List: {message}", "danger")
    return redirect(url_for("dashboard.index"))


@bp_api.route("/test_feed", methods=["POST"])
@login_required
def api_test_feed():
    try:
        data = request.get_json()
        if not data:
            return api_error("No data provided", "VALIDATION_ERROR", 400)

        name = data.get("name", "Test")
        url = data.get("url")
        data_format = data.get("format", "text")
        key_or_column = data.get("key_or_column")

        source_config = {"name": name, "url": url, "format": data_format, "key_or_column": key_or_column}

        success, message, sample = test_feed_source(source_config)

        if success:
            return api_response({"sample": sample}, message=message)
        else:
            return api_error(message, "FEED_TEST_FAILED", 400)
    except Exception as e:
        logger.error(f"Feed test error: {e}", exc_info=True)
        return api_error("Failed to test feed source", "FEED_TEST_ERROR", 500)


# --- SOAR Integration Endpoints ---


@bp_api.route("/indicators", methods=["POST"])
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

        action_type = data.get("type")  # whitelist or blacklist
        value = data.get("value")
        comment = data.get("comment", "Added via API")
        item_type = data.get("item_type", "ip")

        if not value or not action_type:
            return api_error("Missing value or type", "VALIDATION_ERROR", 400)

        # Validation
        is_valid, _ = validate_indicator(value)
        if not is_valid:
            return api_error(f'"{value}" is not a valid IP, CIDR, or Domain/URL', "VALIDATION_ERROR", 400)

        if action_type.lower() == "whitelist":
            success, msg = add_whitelist_item(value, item_type=item_type, description=comment)

        elif action_type.lower() == "blacklist":
            success, msg = add_api_blacklist_item(value, item_type=item_type, comment=comment)
            if success:
                regenerate_edl_files()
        else:
            return api_error("Invalid type. Use whitelist or blacklist", "VALIDATION_ERROR", 400)

        if success:
            return api_response({"value": value, "type": action_type}, message=msg)
        else:
            return api_error(msg, "INDICATOR_ADD_FAILED", 400)

    except Exception as e:
        logger.error(f"API Error adding indicator: {e}", exc_info=True)
        return api_error("Failed to add indicator", "INDICATOR_ADD_ERROR", 500)


def _handle_api_indicator_removal(value, type_hint):
    """Helper to perform the actual removal from DB."""
    deleted = False
    msgs = []

    # Try Blacklist
    if not type_hint or type_hint == "blacklist":
        if remove_api_blacklist_item(value):
            deleted = True
            msgs.append("Removed from Blacklist")

    # Try Whitelist
    if not type_hint or type_hint == "whitelist":
        w_list = get_whitelist()
        found_id = next((item["id"] for item in w_list if item["item"] == value), None)

        if found_id and remove_whitelist_item(found_id):
            deleted = True
            msgs.append("Removed from Whitelist")

    return deleted, msgs


@bp_api.route("/indicators", methods=["DELETE"])
@api_key_required
def remove_indicator():
    """
    Remove an indicator via API.
    """
    try:
        data = request.get_json()
        if not data or not data.get("value"):
            return api_error("Missing value", "VALIDATION_ERROR", 400)

        value = data.get("value")
        type_hint = data.get("type")

        deleted, msgs = _handle_api_indicator_removal(value, type_hint)

        if deleted:
            regenerate_edl_files()
            return api_response({"value": value}, message=", ".join(msgs))

        return api_error("Item not found", "NOT_FOUND", 404)

    except Exception as e:
        logger.error(f"API Error removing indicator: {e}", exc_info=True)
        return api_error("Failed to remove indicator", "INDICATOR_REMOVE_ERROR", 500)


from .auth import api_key_required

# --- FortiDeceptor Integration ---


@bp_api.route("/deceptor/block", methods=["POST"])
@api_key_required
def deceptor_block():
    """
    FortiDeceptor integration for blocking multiple IPs.
    """
    logger.info(f"CRITICAL: Deceptor Block Function reached! Client IP: {request.remote_addr}")
    try:
        # 1. Capture Raw Data for Debugging
        raw_headers = _sanitize_headers_for_log(request.headers)
        raw_body = request.get_data(as_text=True)
        data_all = request.get_json(silent=True) or request.form

        logger.info(f"Deceptor Request Details | Headers: {raw_headers} | Body length: {len(raw_body)}")

        # 2. Extract IP(s) from various locations - Prioritize Body for actual data
        input_data = data_all.get("whblockdata") or data_all.get("whblockheader") or data_all.get("Hacker-IP")

        # Fallback to headers if body is empty
        if not input_data:
            input_data = request.headers.get("whblockheader") or request.headers.get("Hacker-IP")

        if not input_data:
            # Fallback regex scan in body
            import re

            ip_matches = re.findall(r"(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})", raw_body)
            if ip_matches:
                input_data = ",".join(ip_matches)

        if not input_data:
            logger.error(f"Deceptor BLOCK Failed: No IP found in request (body length: {len(raw_body)})")
            return jsonify({"status": "error", "message": "No IP found"}), 400

        # 3. Process Multiple IPs (Split by comma or space)
        import re

        # Normalize delimiters to comma
        normalized_ips = re.sub(r"[\s,;]+", ",", input_data).strip(",")
        ip_list = [ip.strip() for ip in normalized_ips.split(",") if ip.strip()]

        config = read_config()
        default_lifetime_days = config.get("indicator_lifetime_days", 30)

        expiry_input = data_all.get("expiry")
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
                success, _ = add_api_blacklist_item(
                    ip, item_type="ip", comment=comment, expires_at=expires_at, source="FortiDeceptor"
                )
                if success:
                    added_count += 1
                    successful_indicators.append((ip, "Unknown", "ip"))
            else:
                logger.warning(f"Skipping invalid IP from Deceptor: {ip}")

        if successful_indicators:
            # Bulk upsert once to reduce DB transaction overhead for multi-IP payloads.
            try:
                upsert_indicators_bulk(successful_indicators, source_name="FortiDeceptor")
            except Exception as db_err:
                logger.error(f"Failed to upsert Deceptor indicators to main DB: {db_err}")

        # Regenerate EDL files in background thread so firewalls pick up new blocks quickly
        regenerate_edl_files()

        # ALWAYS return success 200 if the request reached here with valid API Key
        # This prevents Deceptor from showing "Failed" status during probes
        return jsonify({"status": "success", "message": f"Processed {added_count} indicators."}), 200

    except Exception as e:
        logger.error(f"FortiDeceptor API Error: {e}", exc_info=True)
        return jsonify({"status": "error", "message": "Internal server error"}), 500


# --- JSON API Endpoints for ITAI Adapter ---


@bp_api.route("/whitelist")
@login_required
def get_whitelist_api():
    """Returns paginated whitelist as JSON."""
    page = request.args.get("page", 1, type=int)
    per_page = request.args.get("per_page", 50, type=int)

    all_items = get_whitelist()
    total = len(all_items)
    start = (page - 1) * per_page
    end = start + per_page
    items = all_items[start:end]

    return api_response(
        {
            "items": items,
            "total": total,
            "page": page,
            "per_page": per_page,
        }
    )


@bp_api.route("/blacklist")
@login_required
def get_blacklist_api():
    """Returns paginated API blacklist as JSON."""
    page = request.args.get("page", 1, type=int)
    per_page = request.args.get("per_page", 50, type=int)

    all_items = get_api_blacklist_items()
    total = len(all_items)
    start = (page - 1) * per_page
    end = start + per_page
    items = all_items[start:end]

    return api_response(
        {
            "items": items,
            "total": total,
            "page": page,
            "per_page": per_page,
        }
    )


@bp_api.route("/safe_list/add_api", methods=["POST"])
@login_required
@permission_required("system", "rw")
def add_safe_list_item_api():
    """JSON version of safe list add — accepts application/json body."""
    data = request.get_json(silent=True) or {}
    item = data.get("item", "").strip()
    if not item:
        return api_error("item is required", "VALIDATION_ERROR", 400)

    is_valid, _ = validate_indicator(item)
    if not is_valid:
        return api_error(
            f'"{item}" is not a valid IP, CIDR, or Domain/URL.',
            "VALIDATION_ERROR",
            400,
        )

    success, message = add_to_safe_list(item)
    if success:
        return api_response({"added": item})
    return api_error(message, "SAFE_LIST_ADD_FAILED", 400)


@bp_api.route("/safe_list/remove_api", methods=["POST"])
@login_required
@permission_required("system", "rw")
def remove_safe_list_item_api():
    """JSON version of safe list remove — accepts application/json body."""
    data = request.get_json(silent=True) or {}
    item = data.get("item", "").strip()
    if not item:
        return api_error("item is required", "VALIDATION_ERROR", 400)

    success, message = remove_from_safe_list(item)
    if success:
        return api_response({"removed": item})
    return api_error(message, "SAFE_LIST_REMOVE_FAILED", 400)


@bp_api.route("/backup_api", methods=["POST"])
@login_required
@permission_required("system", "rw")
def backup_system_api():
    """JSON version of backup — saves zip to DATA_DIR and returns path."""
    try:
        from ..services.audit_service import log_action

        username = session.get("username", "unknown")
        log_action(
            username,
            "backup_api",
            ip_address=request.remote_addr,
            details=f"User: {username}",
        )

        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        backup_filename = f"threat_feed_backup_{timestamp}.zip"
        backup_path = os.path.join(DATA_DIR, backup_filename)

        with zipfile.ZipFile(backup_path, "w", zipfile.ZIP_DEFLATED) as zf:
            files_to_backup = ["config.json", "threat_feed.db", "safe_list.txt", "jobs.sqlite"]
            for filename in files_to_backup:
                file_path = os.path.join(DATA_DIR, filename)
                if os.path.exists(file_path):
                    zf.write(file_path, filename)

        return api_response({"path": backup_path, "filename": backup_filename}, message="Backup created")
    except Exception as e:
        logger.error(f"Backup API error: {e}", exc_info=True)
        return api_error("Failed to create backup", "BACKUP_ERROR", 500)


@bp_api.route("/restore_api", methods=["POST"])
@login_required
@permission_required("system", "rw")
def restore_system_api():
    """JSON version of restore — accepts base64-encoded zip in body."""
    import base64

    data = request.get_json(silent=True) or {}
    zip_b64 = data.get("zip_data", "").strip()
    if not zip_b64:
        return api_error("zip_data (base64-encoded zip) is required", "VALIDATION_ERROR", 400)

    try:
        zip_bytes = base64.b64decode(zip_b64)
    except Exception:
        return api_error("zip_data is not valid base64", "VALIDATION_ERROR", 400)

    try:
        with zipfile.ZipFile(io.BytesIO(zip_bytes)) as zf:
            valid_files = ["config.json", "threat_feed.db", "safe_list.txt", "jobs.sqlite"]
            for name in zf.namelist():
                if name not in valid_files:
                    return api_error(
                        f"Unexpected file in archive: {name}",
                        "VALIDATION_ERROR",
                        400,
                    )
                dest = os.path.realpath(os.path.join(DATA_DIR, name))
                if not dest.startswith(os.path.realpath(DATA_DIR) + os.sep):
                    return api_error(
                        f"Path traversal detected: {name}",
                        "VALIDATION_ERROR",
                        400,
                    )
                with zf.open(name) as src, open(dest, "wb") as dst:
                    dst.write(src.read())

        update_scheduled_jobs()

        from ..services.audit_service import log_action

        username = session.get("username", "unknown")
        log_action(
            username,
            "restore_api",
            ip_address=request.remote_addr,
            details=f"User: {username}",
        )

        return api_response({"restored": True}, message="System restored successfully. Configuration reloaded.")
    except Exception as e:
        logger.error(f"Restore API error: {e}", exc_info=True)
        return api_error("Failed to restore system", "RESTORE_ERROR", 500)


@bp_api.route("/deceptor/unblock", methods=["POST"])
@api_key_required
def deceptor_unblock():
    """
    FortiDeceptor integration for unblocking one or more IPs.
    Supports comma/space-separated multi-IP payloads and all common field locations.
    """
    import re as _re

    try:
        raw_body = request.get_data(as_text=True)
        data_all = request.get_json(silent=True) or request.form

        logger.info(f"Deceptor UNBLOCK request | Client IP: {request.remote_addr} | Body length: {len(raw_body)}")

        # 1. Extract raw IP string — check all possible locations FortiDeceptor may use
        input_data = (
            request.headers.get("whunblockheader")
            or request.headers.get("whblockheader")
            or request.headers.get("Hacker-IP")
            or data_all.get("whunblockdata")
            or data_all.get("whblockdata")
            or data_all.get("whblockheader")
            or data_all.get("Hacker-IP")
        )

        # Fallback: regex scan raw body for all IPv4s
        if not input_data:
            matches = _re.findall(r"(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})", raw_body)
            if matches:
                input_data = ",".join(matches)
                logger.info(f"Deceptor UNBLOCK: IPs extracted via regex fallback: {input_data}")

        if not input_data:
            logger.error(f"Deceptor UNBLOCK Failed: No IP found in request (body length: {len(raw_body)})")
            return jsonify({"status": "error", "message": "Missing IP"}), 400

        # 2. Normalize and split — FortiDeceptor may send multiple IPs as "ip1, ip2"
        normalized = _re.sub(r"[\s,;]+", ",", input_data).strip(",")
        ip_list = [ip.strip() for ip in normalized.split(",") if ip.strip()]

        removed_count = 0
        skipped = []
        for ip in ip_list:
            is_valid, _ = validate_indicator(ip)
            if not is_valid:
                logger.warning(f"Deceptor UNBLOCK: invalid indicator skipped: {ip}")
                skipped.append(ip)
                continue
            if remove_api_blacklist_item(ip):
                removed_count += 1
                logger.info(f"Deceptor UNBLOCK: {ip} removed from blacklist.")
            else:
                logger.info(f"Deceptor UNBLOCK: {ip} not in blacklist (already removed).")

        if removed_count > 0:
            regenerate_edl_files()

        # Always return 200 so FortiDeceptor doesn't retry for already-removed entries
        return jsonify(
            {
                "status": "success",
                "message": f"Processed {len(ip_list)} IP(s): {removed_count} removed from blacklist.",
                "removed": removed_count,
                "skipped_invalid": skipped,
            }
        ), 200

    except Exception as e:
        logger.error(f"FortiDeceptor UNBLOCK API Error: {e}", exc_info=True)
        return jsonify({"status": "error", "message": "Internal server error"}), 500
