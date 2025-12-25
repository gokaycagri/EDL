from flask import Blueprint, render_template, request, jsonify, current_app
from .auth import login_required
import requests
import logging
import whois # Added for WHOIS lookup
from ..utils import get_proxy_settings

bp_tools = Blueprint('tools', __name__, url_prefix='/tools')
logger = logging.getLogger(__name__)

@bp_tools.route('/investigate')
@login_required
def investigate():
    return render_template('investigate.html')

@bp_tools.route('/api/lookup_ip', methods=['POST'])
@login_required
def lookup_ip():
    whois_data_str = "WHOIS lookup failed or no data available."
    try:
        data = request.get_json()
        ip_address = data.get('ip')
        
        if not ip_address:
            return jsonify({'success': False, 'error': 'No IP address provided'}), 400
            
        # Perform WHOIS lookup
        try:
            whois_info = whois.whois(ip_address)
            # The whois library returns a WhoisEntry object, which has a 'text' attribute for raw output
            whois_data_str = whois_info.text if whois_info and whois_info.text else "No WHOIS data found."
        except Exception as whois_e:
            logger.warning(f"WHOIS lookup failed for {ip_address}: {whois_e}")
            whois_data_str = f"WHOIS lookup error: {whois_e}"

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
        proxies, _, _ = get_proxy_settings()
        response = requests.post(target_url, json=payload, headers=headers, timeout=10, proxies=proxies)
        
        if response.status_code == 200:
            thc_data = response.json()
            return jsonify({'success': True, 'data': thc_data, 'whois_data': whois_data_str})
        else:
             return jsonify({'success': False, 'error': f"External API returned {response.status_code}"}), 502
             
    except Exception as e:
        logger.error(f"Error in lookup_ip: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500
