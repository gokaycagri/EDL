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
        config = read_config()
        
        client_ip = request.remote_addr
        if request.headers.getlist("X-Forwarded-For"):
             client_ip = request.headers.getlist("X-Forwarded-For")[0]

        # Support both X-API-KEY and standard Authorization header
        request_key = request.headers.get("X-API-KEY")
        if not request_key:
            auth_header = request.headers.get("Authorization")
            if auth_header:
                # Handle "Bearer <key>" or just "<key>"
                if auth_header.lower().startswith("bearer "):
                    request_key = auth_header[7:].strip()
                else:
                    request_key = auth_header.strip()
                
                # Robustness: Remove quotes if added by the client
                request_key = request_key.replace('"', '').replace("'", "")

        if not request_key:
            logger.warning(f"API Access Refused: Missing Key from {client_ip} to {request.path}")
            return jsonify({"status": "error", "message": "Unauthorized: Missing API Key"}), 401

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
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        if username and password:
            success, message, info = check_credentials(username, password)
            if success:
                # Check for MFA
                if is_mfa_enabled(username):
                    session['pre_mfa_auth'] = {
                        'username': username,
                        'permissions': info.get('permissions', {}),
                        'profile_name': info.get('profile_name', 'Local')
                    }
                    return redirect(url_for('auth.verify_2fa'))
                
                # No MFA, login directly
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
    if 'pre_mfa_auth' not in session:
        return redirect(url_for('auth.login'))
        
    if request.method == 'POST':
        code = request.form.get('code')
        user_data = session['pre_mfa_auth']
        username = user_data['username']
        
        secret = get_user_mfa_secret(username)
        if verify_totp(secret, code):
            # Success
            session['logged_in'] = True
            session['username'] = username
            session['permissions'] = user_data['permissions']
            session['profile_name'] = user_data['profile_name']
            session.pop('pre_mfa_auth', None)
            return redirect(url_for('dashboard.index'))
        else:
            logger.warning(f"2FA verification failed for user: {username}")
            flash('Invalid Code', 'danger')
            
    return render_template('login_2fa.html')

@bp_auth.route('/mfa/setup', methods=['GET'])
@login_required
def setup_mfa():
    secret = generate_totp_secret()
    qr_b64 = generate_qr_code(session['username'], secret)
    return jsonify({
        'secret': secret,
        'qr_code': qr_b64
    })

@bp_auth.route('/mfa/enable', methods=['POST'])
@login_required
def enable_mfa():
    data = request.get_json()
    secret = data.get('secret')
    code = data.get('code')
    username = session.get('username')
    
    logger.info(f"Attempting to enable MFA for user: {username}")
    
    if verify_totp(secret, code):
        success, msg = update_user_mfa_secret(username, secret)
        if success:
            logger.info(f"MFA successfully enabled for user: {username}")
            return jsonify({'status': 'success', 'message': 'MFA Enabled Successfully'})
        else:
            logger.error(f"Failed to update MFA secret for user {username}: {msg}")
            return jsonify({'status': 'error', 'message': f'Database error: {msg}'})
    else:
        logger.warning(f"MFA enablement failed for user {username}: Invalid Code")
        return jsonify({'status': 'error', 'message': 'Invalid Code'})

@bp_auth.route('/mfa/disable', methods=['POST'])
@login_required
def disable_mfa():
    update_user_mfa_secret(session['username'], None)
    return jsonify({'status': 'success', 'message': 'MFA Disabled'})

@bp_auth.route('/logout')
def logout():
    session.pop('logged_in', None)
    session.pop('username', None)
    session.pop('pre_mfa_auth', None)
    return redirect(url_for('dashboard.index'))
