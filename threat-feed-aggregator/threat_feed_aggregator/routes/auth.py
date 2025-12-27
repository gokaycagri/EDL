import logging
from flask import render_template, request, session, redirect, url_for, flash, jsonify
from functools import wraps
from ..auth_manager import check_credentials
from ..config_manager import read_config
from . import bp_auth

logger = logging.getLogger(__name__)

def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'logged_in' not in session:
            return redirect(url_for('auth.login', next=request.url))
        return f(*args, **kwargs)
    return decorated_function

def api_key_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        config = read_config()
        
        request_key = request.headers.get("X-API-KEY")
        if not request_key:
            return jsonify({"status": "error", "message": "Unauthorized: Missing X-API-KEY header"}), 401
            
        # Check against API Clients list
        api_clients = config.get("api_clients", [])
        
        # Backward compatibility for single key
        old_global_key = config.get("api_key")
        old_allowed_hosts = config.get("api_allowed_hosts", [])
        
        valid_client = None
        
        # 1. Check New Client List
        for client in api_clients:
            if client.get("api_key") == request_key:
                valid_client = client
                break
        
        # 2. Fallback to Old Config
        if not valid_client and old_global_key and request_key == old_global_key:
             valid_client = {"name": "Legacy Global", "allowed_ips": [h['ip'] for h in old_allowed_hosts]}

        if not valid_client:
            return jsonify({"status": "error", "message": "Unauthorized: Invalid API Key"}), 401
            
        # Trusted Host Check
        allowed_ips = valid_client.get("allowed_ips", [])
        if allowed_ips:
            client_ip = request.remote_addr
            if request.headers.getlist("X-Forwarded-For"):
                 client_ip = request.headers.getlist("X-Forwarded-For")[0]

            if client_ip not in allowed_ips:
                 return jsonify({"status": "error", "message": f"Unauthorized Host: {client_ip}"}), 403

        return f(*args, **kwargs)
    return decorated_function

@bp_auth.route('/login', methods=['GET', 'POST'])
def login():
    error = None
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        
        if username and password:
            success, message, info = check_credentials(username, password)
            if success:
                session['logged_in'] = True
                session['username'] = username
                session['permissions'] = info.get('permissions', {})
                session['profile_name'] = info.get('profile_name', 'Local')
                flash(message, 'success')
                return redirect(url_for('dashboard.index'))
            else:
                flash(message, 'danger')

    return render_template('login.html', error=error)

@bp_auth.route('/logout')
def logout():
    session.pop('logged_in', None)
    session.pop('username', None)
    return redirect(url_for('dashboard.index'))
