import logging

from flask import Blueprint, jsonify, render_template, request

from ..response_helpers import api_error, api_response
from .auth import login_required

bp_tools = Blueprint('tools', __name__, url_prefix='/tools')
logger = logging.getLogger(__name__)

@bp_tools.route('/investigate')
@login_required
def investigate():
    return render_template('investigate.html')

@bp_tools.route('/api/lookup_ip', methods=['POST'])
@login_required
def lookup_ip():
    try:
        data = request.get_json()
        ip_address = data.get('ip')

        if not ip_address:
            return api_error("No IP address provided", "VALIDATION_ERROR", 400)

        # Validate IP address format
        import ipaddress
        try:
            ip_obj = ipaddress.ip_address(ip_address.strip())
        except ValueError:
            return api_error("Invalid IP address format", "VALIDATION_ERROR", 400)
        ip_address = str(ip_obj)

        from ..services.investigation_service import InvestigationService
        result = InvestigationService.lookup_ip(ip_address)

        return api_response(result)

    except Exception as e:
        logger.error(f"Error in lookup_ip: {e}")
        return api_error(str(e), "LOOKUP_ERROR", 500)

@bp_tools.route('/api/lookup_internal', methods=['POST'])
@login_required
def lookup_internal():
    try:
        data = request.get_json()
        indicator = data.get('indicator')

        if not indicator:
            return api_error("No indicator provided", "VALIDATION_ERROR", 400)

        from ..db_manager import get_sources_for_indicator, get_api_blacklist_item_by_value

        # 1. Fetch from main DB (indicator_sources table)
        sources = get_sources_for_indicator(indicator)

        # 2. Check API Blacklist (Manual/Deceptor Blocks) for metadata like comments
        blacklist_item = get_api_blacklist_item_by_value(indicator)

        if blacklist_item:
            comment = blacklist_item.get('comment') or ""
            blacklist_source_name = "Manual Blacklist"
            if "FortiDeceptor" in comment:
                blacklist_source_name = "FortiDeceptor"

            existing_idx = next((i for i, s in enumerate(sources) if s['source_name'] == blacklist_source_name), None)

            if existing_idx is not None:
                sources[existing_idx]['comment'] = comment
                sources.insert(0, sources.pop(existing_idx))
            else:
                sources.insert(0, {
                    'source_name': blacklist_source_name,
                    'last_seen': blacklist_item['added_at'],
                    'comment': comment
                })

        return api_response({"indicator": indicator, "sources": sources})

    except Exception as e:
        logger.error(f"Error in lookup_internal: {e}")
        return api_error(str(e), "LOOKUP_ERROR", 500)

@bp_tools.route('/dns_deduplication')
@login_required
def dns_deduplication():
    from ..config_manager import read_config
    config = read_config()
    schedule_config = config.get('dns_dedup_schedule', {})
    return render_template('dns_deduplication.html', schedule=schedule_config)

@bp_tools.route('/api/dns_deduplication/schedule', methods=['POST'])
@login_required
def save_dedup_schedule():
    from ..config_manager import read_config, write_config
    from ..scheduler_manager import update_scheduled_jobs
    
    try:
        config = read_config()
        
        enabled = request.form.get('enabled') == 'on'
        auto_delete = request.form.get('auto_delete') == 'on'
        start_time = request.form.get('start_time', '00:00')
        end_time = request.form.get('end_time', '23:59')
        interval = request.form.get('interval', type=int) or 60
        batch_size = request.form.get('batch_size', type=int) or 50
        
        config['dns_dedup_schedule'] = {
            'enabled': enabled,
            'auto_delete': auto_delete,
            'start_time': start_time,
            'end_time': end_time,
            'interval_minutes': interval,
            'batch_size': batch_size
        }
        
        write_config(config)
        update_scheduled_jobs()
        
        return api_response(message="Schedule updated successfully.")
    except Exception as e:
        logger.error(f"Error saving schedule: {e}")
        return api_error(str(e), "SCHEDULE_ERROR", 500)

@bp_tools.route('/api/dns_deduplication/analyze', methods=['POST'])
@login_required
def analyze_dns_duplicates():
    try:
        import asyncio
        from ..services.dns_deduplication import process_background_dns_batch, run_deduplication_sweep

        logger.info("DNS Deduplication Analyze: Manual run requested.")
        
        # Trigger single batch processing
        processed_count = asyncio.run(process_background_dns_batch(batch_size=50))
        
        # Trigger sweep immediately
        deleted_count = run_deduplication_sweep()
        logger.info(
            f"DNS Deduplication Analyze: Completed manual run (resolved={processed_count}, deleted={deleted_count})."
        )
        
        return api_response(
            {"resolved": processed_count, "deleted": deleted_count, "duplicates": []},
            message=f"Analysis complete. Resolved {processed_count}, Deleted {deleted_count}."
        )
    except Exception as e:
        logger.error(f"Error in analyze_dns_duplicates: {e}")
        return api_error(str(e), "DNS_DEDUP_ERROR", 500)

@bp_tools.route('/api/dns_deduplication/delete', methods=['POST'])
@login_required
def delete_dns_duplicates():
    try:
        data = request.get_json()
        indicators = data.get('indicators', [])

        if not indicators:
            return api_error("No indicators provided", "VALIDATION_ERROR", 400)

        from ..db_manager import delete_indicators
        count = delete_indicators(indicators)

        return api_response({"deleted_count": count})
    except Exception as e:
        logger.error(f"Error in delete_dns_duplicates: {e}")
        return api_error(str(e), "DNS_DELETE_ERROR", 500)
