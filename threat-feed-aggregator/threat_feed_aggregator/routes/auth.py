from functools import wraps
import logging
from urllib.parse import urlparse

from flask import flash, redirect, render_template, request, session, url_for

from ..auth_manager import check_credentials, verify_totp
from ..config_manager import read_config
from ..db_manager import get_user_mfa_secret, is_mfa_enabled
from ..response_helpers import api_error
from . import bp_auth

logger = logging.getLogger(__name__)


def _safe_next_url(target: str | None) -> str | None:
    """Return target only if it is a safe relative path (no scheme/host).

    Prevents open-redirect attacks: an attacker could craft
    ?next=https://evil.com to hijack post-login redirects.
    Only paths that start with '/' and carry no netloc are accepted.
    """
    if not target:
        return None
    parsed = urlparse(target)
    if parsed.scheme or parsed.netloc:
        return None
    # Must be an absolute path (starts with /) to avoid protocol-relative URLs
    if not target.startswith("/"):
        return None
    return target


def _login_next() -> str:
    """Return the current request path+query as a safe relative URL for ?next=."""
    path = request.path
    qs = request.query_string.decode("utf-8", errors="replace")
    return f"{path}?{qs}" if qs else path


def _normalize_api_key(auth_value):
    if not auth_value:
        return None

    cleaned = auth_value.strip()
    if not cleaned:
        return None

    scheme_and_value = cleaned.split(None, 1)
    if len(scheme_and_value) == 2 and scheme_and_value[0].lower() == "bearer":
        return scheme_and_value[1].strip()

    return cleaned


def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if "logged_in" not in session:
            return redirect(url_for("auth.login", next=_login_next()))
        return f(*args, **kwargs)

    return decorated_function


def api_key_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if session.get("logged_in"):
            return f(*args, **kwargs)

        config = read_config()
        # Use remote_addr only — X-Forwarded-For is client-spoofable.
        # Configure Flask ProxyFix middleware if behind a trusted reverse proxy.
        client_ip = request.remote_addr

        auth_header = (
            request.headers.get("Authorization")
            or request.headers.get("X-API-KEY")
            or request.headers.get("Api-Key")
            or request.form.get("api_key")
        )

        request_key = _normalize_api_key(auth_header)

        if request_key:
            logger.info(f"API Access Attempt | Key: {request_key[:6]}*** | IP: {client_ip}")
        else:
            logger.warning(f"API Key Missing! IP: {client_ip} Path: {request.path}")
            return api_error("Unauthorized: Missing API Key", "AUTH_MISSING_KEY", 401)

        import hmac

        api_clients = config.get("api_clients", [])
        valid_client = next(
            (c for c in api_clients if hmac.compare_digest(c.get("api_key", ""), request_key)),
            None,
        )

        global_key = config.get("api_key", "")
        if not valid_client and global_key and hmac.compare_digest(global_key, request_key):
            valid_client = {"name": "Global", "allowed_ips": []}

        if not valid_client:
            logger.warning(f"Unauthorized Key from {client_ip}: {request_key[:10]}...")
            return api_error("Unauthorized: Invalid API Key", "AUTH_INVALID_KEY", 401)

        allowed_ips = valid_client.get("allowed_ips", [])
        if allowed_ips and client_ip not in allowed_ips:
            logger.warning(f"IP Forbidden: {client_ip} not in {allowed_ips}")
            return api_error(f"Forbidden Host: {client_ip}", "AUTH_IP_FORBIDDEN", 403)

        return f(*args, **kwargs)

    return decorated_function


def basic_auth_required(f):
    """
    HTTP Basic Authentication decorator.
    Validates username:password against EDL local user accounts.

    Trend Micro DDEI ve benzeri cihazlar API key yerine
    Basic Auth (kullanıcı adı + şifre) gönderdiğinde bu decorator kullanılır.

    DDEI'ye şu şekilde tanımlanır:
      URL:      https://edl.mfa.gov.tr/api/ddei/submit
      Username: <EDL local kullanıcı adı>
      Password: <EDL local kullanıcı şifresi>
    """
    import base64

    @wraps(f)
    def decorated_function(*args, **kwargs):
        # Zaten web oturumu varsa geçir
        if session.get("logged_in"):
            return f(*args, **kwargs)

        client_ip = request.remote_addr
        auth_header = request.headers.get("Authorization", "")

        # Basic Auth header kontrolü: "Basic base64(user:pass)"
        if not auth_header.lower().startswith("basic "):
            logger.warning(f"DDEI Basic Auth: Missing/invalid Authorization header. IP: {client_ip}")
            response = api_error("Unauthorized: Basic Auth required", "AUTH_MISSING", 401)
            response.headers["WWW-Authenticate"] = 'Basic realm="EDL API"'
            return response

        try:
            credentials = base64.b64decode(auth_header[6:]).decode("utf-8", errors="ignore")
            username, _, password = credentials.partition(":")
        except Exception:
            logger.warning(f"DDEI Basic Auth: Failed to decode credentials. IP: {client_ip}")
            return api_error("Unauthorized: Malformed credentials", "AUTH_MALFORMED", 401)

        if not username or not password:
            logger.warning(f"DDEI Basic Auth: Empty username or password. IP: {client_ip}")
            return api_error("Unauthorized: Username and password required", "AUTH_EMPTY", 401)

        # EDL local kullanıcıları ile doğrula
        from ..auth_manager import check_credentials

        success, _msg, _info = check_credentials(username, password)
        if not success:
            logger.warning(f"DDEI Basic Auth: Invalid credentials for '{username}'. IP: {client_ip}")
            return api_error("Unauthorized: Invalid username or password", "AUTH_INVALID", 401)

        logger.info(f"DDEI Basic Auth: Authenticated as '{username}'. IP: {client_ip}")
        return f(*args, **kwargs)

    return decorated_function



@bp_auth.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form.get("username", "")
        password = request.form.get("password", "")
        if username and password:
            success, message, info = check_credentials(username, password)
            if success:
                from ..services.audit_service import log_action

                log_action(username, "login", ip_address=request.remote_addr)
                next_url = _safe_next_url(request.args.get("next"))
                if is_mfa_enabled(username):
                    session.clear()
                    session["pre_mfa_auth"] = {
                        "username": username,
                        "permissions": info.get("permissions", {}),
                        "profile_name": info.get("profile_name", "Local"),
                        "next": next_url,
                    }
                    return redirect(url_for("auth.verify_2fa"))
                # Regenerate session to prevent session fixation
                session.clear()
                session["logged_in"] = True
                session["username"] = username
                session["permissions"] = info.get("permissions", {})
                session["profile_name"] = info.get("profile_name", "Local")
                flash(message, "success")
                return redirect(next_url or url_for("dashboard.index"))
            else:
                from ..services.audit_service import log_action

                log_action(username, "login_failed", ip_address=request.remote_addr)
                flash(message, "danger")
    return render_template("login.html")


@bp_auth.route("/login/verify-2fa", methods=["GET", "POST"])
def verify_2fa():
    if "pre_mfa_auth" not in session:
        return redirect(url_for("auth.login"))
    if request.method == "POST":
        code = request.form.get("code")
        user_data = session["pre_mfa_auth"]
        username = user_data["username"]
        secret = get_user_mfa_secret(username)
        if verify_totp(secret, code, username=username):
            next_url = _safe_next_url(user_data.get("next"))
            # Regenerate session to prevent session fixation
            session.clear()
            session["logged_in"] = True
            session["username"] = username
            session["permissions"] = user_data["permissions"]
            session["profile_name"] = user_data["profile_name"]
            return redirect(next_url or url_for("dashboard.index"))
        else:
            flash("Invalid Code", "danger")
    return render_template("login_2fa.html")


@bp_auth.route("/logout", methods=["POST"])
def logout():
    session.clear()
    return redirect(url_for("auth.login"))
