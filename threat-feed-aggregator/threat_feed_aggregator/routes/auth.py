import logging
from functools import wraps
from flask import flash, jsonify, redirect, render_template, request, session, url_for
from ..auth_manager import check_credentials, generate_totp_secret, generate_qr_code, verify_totp
from ..db_manager import is_mfa_enabled, update_user_mfa_secret, get_user_mfa_secret
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
        if session.get('logged_in'):
            return f(*args, **kwargs)

        config = read_config()
        client_ip = request.remote_addr
        if request.headers.getlist('X-Forwarded-For'):
             client_ip = request.headers.getlist('X-Forwarded-For')[0]

        request_key = None
        auth_header = request.headers.get('Authorization') or request.headers.get('X-API-KEY')
        
        if auth_header:
            import re
            # Step 1: Remove any quotes, colons, and joiners
            cleaned = auth_header.replace('"', '').replace("'", "").replace(':', '').strip()
            
            # Step 2: Extract key if 'Bearer' exists (case insensitive)
            # Handle cases like 'bearer4Sb...', 'bearer 4Sb...', or 'Bearer Bearer 4Sb...'
            match = re.search(r'(?:bearer\s*)?([a-zA-Z0-9]{10,})', cleaned, re.IGNORECASE)
            if match:
                request_key = match.group(1)
            else:
                request_key = cleaned

        if request_key:
            logger.info(f"API Access Attempt | Final Key: {request_key[:10]}... | IP: {client_ip}")
        else:
            logger.warning(f"API Key Missing! Headers: {dict(request.headers)}")
            return jsonify({'status': 'error', 'message': 'Unauthorized: Missing API Key'}), 401

        api_clients = config.get('api_clients', [])
        valid_client = next((c for c in api_clients if c.get('api_key') == request_key), None)

        if not valid_client and request_key == config.get('api_key'):
             valid_client = {'name': 'Global', 'allowed_ips': []}

        if not valid_client:
            logger.warning(f"Unauthorized Key from {client_ip}: {request_key[:10]}...")
            return jsonify({'status': 'error', 'message': 'Unauthorized: Invalid API Key'}), 401

        allowed_ips = valid_client.get('allowed_ips', [])
        if allowed_ips and client_ip not in allowed_ips:
             logger.warning(f"IP Forbidden: {client_ip} not in {allowed_ips}")
             return jsonify({'status': 'error', 'message': f'Forbidden Host: {client_ip}'}), 403

        return f(*args, **kwargs)
    return decorated_function

@bp_auth.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        if username and password:
            success, message, info = check_credentials(username, password)
            if success:
                if is_mfa_enabled(username):
                    session['pre_mfa_auth'] = {'username': username, 'permissions': info.get('permissions', {}), 'profile_name': info.get('profile_name', 'Local')}
                    return redirect(url_for('auth.verify_2fa'))
                session['logged_in'] = True
                session['username'] = username
                session['permissions'] = info.get('permissions', {})
                session['profile_name'] = info.get('profile_name', 'Local')
                flash(message, 'success')
                return redirect(url_for('dashboard.index'))
            else:
                flash(message, 'danger')
    return render_template('login.html')

@bp_auth.route('/login/verify-2fa', methods=['GET', 'POST'])
def verify_2fa():
    if 'pre_mfa_auth' not in session: return redirect(url_for('auth.login'))
    if request.method == 'POST':
        code = request.form.get('code')
        user_data = session['pre_mfa_auth']
        username = user_data['username']
        secret = get_user_mfa_secret(username)
        if verify_totp(secret, code):
            session['logged_in'] = True
            session['username'] = username
            session['permissions'] = user_data['permissions']
            session['profile_name'] = user_data['profile_name']
            session.pop('pre_mfa_auth', None)
            return redirect(url_for('dashboard.index'))
        else:
            flash('Invalid Code', 'danger')
    return render_template('login_2fa.html')

@bp_auth.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('auth.login'))
