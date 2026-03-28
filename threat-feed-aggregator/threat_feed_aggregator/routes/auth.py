import logging
from functools import wraps

from flask import flash, redirect, render_template, request, session, url_for

from ..auth_manager import check_credentials, verify_totp
from ..config_manager import read_config
from ..db_manager import get_user_mfa_secret, is_mfa_enabled
from ..response_helpers import api_error
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
        # Use remote_addr only — X-Forwarded-For is client-spoofable.
        # Configure Flask ProxyFix middleware if behind a trusted reverse proxy.
        client_ip = request.remote_addr

        request_key = None
        auth_header = request.headers.get('Authorization') or request.headers.get('X-API-KEY')

        if auth_header:
            cleaned = auth_header.strip()
            # Strip Bearer prefix (case insensitive)
            if cleaned.lower().startswith('bearer '):
                request_key = cleaned[7:].strip()
            else:
                request_key = cleaned

        if request_key:
            logger.info(f"API Access Attempt | Key: {request_key[:6]}*** | IP: {client_ip}")
        else:
            logger.warning(f"API Key Missing! IP: {client_ip} Path: {request.path}")
            return api_error("Unauthorized: Missing API Key", "AUTH_MISSING_KEY", 401)

        import hmac

        api_clients = config.get('api_clients', [])
        valid_client = next(
            (c for c in api_clients if hmac.compare_digest(c.get('api_key', ''), request_key)),
            None,
        )

        global_key = config.get('api_key', '')
        if not valid_client and global_key and hmac.compare_digest(global_key, request_key):
             valid_client = {'name': 'Global', 'allowed_ips': []}

        if not valid_client:
            logger.warning(f"Unauthorized Key from {client_ip}: {request_key[:10]}...")
            return api_error("Unauthorized: Invalid API Key", "AUTH_INVALID_KEY", 401)

        allowed_ips = valid_client.get('allowed_ips', [])
        if allowed_ips and client_ip not in allowed_ips:
             logger.warning(f"IP Forbidden: {client_ip} not in {allowed_ips}")
             return api_error(f"Forbidden Host: {client_ip}", "AUTH_IP_FORBIDDEN", 403)

        return f(*args, **kwargs)
    return decorated_function

@bp_auth.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username', '')
        password = request.form.get('password', '')
        if username and password:
            success, message, info = check_credentials(username, password)
            if success:
                from ..services.audit_service import log_action
                log_action(username, 'login', ip_address=request.remote_addr)
                if is_mfa_enabled(username):
                    session.clear()
                    session['pre_mfa_auth'] = {'username': username, 'permissions': info.get('permissions', {}), 'profile_name': info.get('profile_name', 'Local')}
                    return redirect(url_for('auth.verify_2fa'))
                # Regenerate session to prevent session fixation
                session.clear()
                session['logged_in'] = True
                session['username'] = username
                session['permissions'] = info.get('permissions', {})
                session['profile_name'] = info.get('profile_name', 'Local')
                flash(message, 'success')
                return redirect(url_for('dashboard.index'))
            else:
                from ..services.audit_service import log_action
                log_action(username, 'login_failed', ip_address=request.remote_addr)
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
        if verify_totp(secret, code, username=username):
            # Regenerate session to prevent session fixation
            session.clear()
            session['logged_in'] = True
            session['username'] = username
            session['permissions'] = user_data['permissions']
            session['profile_name'] = user_data['profile_name']
            return redirect(url_for('dashboard.index'))
        else:
            flash('Invalid Code', 'danger')
    return render_template('login_2fa.html')

@bp_auth.route('/logout', methods=['POST'])
def logout():
    session.clear()
    return redirect(url_for('auth.login'))
