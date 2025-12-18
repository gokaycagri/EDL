from flask import Blueprint, render_template, request, jsonify, current_app
from .auth import login_required
import requests
import logging

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
            return jsonify({'success': False, 'error': 'No IP address provided'}), 400
            
        # Call ip.thc.org API
        # Documentation: curl https://ip.thc.org/api/v1/lookup -X POST -d' { "ip_address":"1.1.1.1", "limit": 10 }' -s
        
        target_url = "https://ip.thc.org/api/v1/lookup"
        payload = {
            "ip_address": ip_address,
            "limit": 100 
        }
        
        headers = {
            "Content-Type": "application/json",
            "User-Agent": "ThreatFeedAggregator/1.0"
        }
        
        # We need to verify SSL? ip.thc.org likely has valid certs.
        response = requests.post(target_url, json=payload, headers=headers, timeout=10)
        
        if response.status_code == 200:
            return jsonify({'success': True, 'data': response.json()})
        else:
             return jsonify({'success': False, 'error': f"External API returned {response.status_code}"}), 502
             
    except Exception as e:
        logger.error(f"Error querying ip.thc.org: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500
