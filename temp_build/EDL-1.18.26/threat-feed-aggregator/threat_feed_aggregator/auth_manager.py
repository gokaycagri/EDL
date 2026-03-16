import logging
import ssl
import pyotp
import qrcode
import io
import base64

from ldap3 import ALL, Connection, Server, Tls

from .db_manager import get_profile_by_ldap_groups, get_user_permissions, local_user_exists, verify_local_user

logger = logging.getLogger(__name__)

# --- MFA Helpers ---

def generate_totp_secret():
    """Generates a random base32 secret string."""
    return pyotp.random_base32()

def generate_qr_code(username, secret, issuer_name="Threat Feed Aggregator"):
    """Generates a QR code for the TOTP secret."""
    totp_uri = pyotp.totp.TOTP(secret).provisioning_uri(name=username, issuer_name=issuer_name)
    
    qr = qrcode.QRCode(version=1, box_size=10, border=5)
    qr.add_data(totp_uri)
    qr.make(fit=True)
    
    img = qr.make_image(fill_color="black", back_color="white")
    
    # Save to BytesIO
    buffered = io.BytesIO()
    img.save(buffered)
    return base64.b64encode(buffered.getvalue()).decode("utf-8")

def verify_totp(secret, code):
    """Verifies a TOTP code against the secret."""
    if not secret or not code: return False
    
    # Sanitize input: Remove spaces and other whitespace
    code = code.replace(" ", "").strip()
    
    try:
        totp = pyotp.TOTP(secret)
        # valid_window=2 allows for 60s before/after the current time (accommodating drift)
        result = totp.verify(code, valid_window=2)
        if result:
            logger.info("TOTP verification successful.")
        else:
            logger.warning(f"TOTP verification failed for code: {code} (Invalid Code)")
        return result
    except Exception as e:
        logger.error(f"Error during TOTP verification: {e}")
        return False

# --- End MFA Helpers ---

from functools import wraps

from flask import flash, redirect, session, url_for


def permission_required(module, level='r'):
    """
    Decorator to enforce RBAC permissions.
    module: 'dashboard', 'system', or 'tools'
    level: 'r' (Read) or 'rw' (Read-Write)
    """
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            if not session.get('logged_in'):
                return redirect(url_for('auth.login'))

            perms = session.get('permissions', {})
            user_level = perms.get(module, 'none')

            # If level required is 'rw', user must have 'rw'
            # If level required is 'r', user can have 'r' or 'rw'
            has_permission = False
            if level == 'r':
                if user_level in ['r', 'rw']:
                    has_permission = True
            elif level == 'rw':
                if user_level == 'rw':
                    has_permission = True

            if not has_permission:
                logger.warning(f"Permission Denied for user {session.get('username')} on {module}:{level}")
                flash(f"Access Denied: You do not have {level} permissions for {module}.", "danger")
                return redirect(url_for('dashboard.index'))

            return f(*args, **kwargs)
        return decorated_function
    return decorator

def _check_ldap_credentials(username, password):
    """
    Helper function to handle LDAP authentication logic.
    """
    from .config_manager import read_config
    config = read_config()
    auth_config = config.get('auth', {})

    ldap_enabled = auth_config.get('ldap_enabled')
    if ldap_enabled is None:
        ldap_config = auth_config.get('ldap', {})
        ldap_enabled = ldap_config.get('enabled', False)
        servers_list = [ldap_config] if ldap_enabled else []
    else:
        servers_list = auth_config.get('ldap_servers', [])

    if not ldap_enabled:
        return False, "LDAP authentication is disabled.", None

    if not servers_list:
        return False, "LDAP server list is empty.", None

    from .cert_manager import get_ca_bundle_path
    ca_bundle = get_ca_bundle_path()
    last_error = "No LDAP servers responded."

    for srv_config in servers_list:
        server_hostname = srv_config.get('server')
        server_port = srv_config.get('port', 389)
        base_dn = srv_config.get('domain')
        admin_group = srv_config.get('admin_group') # Legacy global group
        ldaps_enabled = srv_config.get('ldaps_enabled', False)

        if not server_hostname or not base_dn:
            continue

        try:
            tls_config = None
            if ldaps_enabled:
                if ca_bundle:
                    tls_config = Tls(validate=ssl.CERT_REQUIRED, ca_certs_file=ca_bundle)
                else:
                    tls_config = Tls(validate=ssl.CERT_NONE)

            server = Server(server_hostname, port=server_port, get_info=ALL, use_ssl=ldaps_enabled, tls=tls_config, connect_timeout=5)

            # Formats to try for Active Directory / LDAP
            possible_dns = []
            if "@" in username or "," in username or "\\" in username:
                possible_dns.append(username)
            else:
                domain_parts = [p.split('=')[1] for p in base_dn.lower().split(',') if p.startswith('dc=')]
                if domain_parts:
                    domain_suffix = ".".join(domain_parts)
                    possible_dns.append(f"{username}@{domain_suffix}")
                possible_dns.append(f"uid={username},ou=people,{base_dn}")
                possible_dns.append(f"cn={username},cn=users,{base_dn}")

            for test_dn in possible_dns:
                logger.info(f"LDAP bind attempt for user {username} with DN: {test_dn}")
                try:
                    conn = Connection(server, user=test_dn, password=password, auto_bind=True)
                    if conn.bound:
                        logger.info(f"LDAP bind SUCCESS for user: {username} (DN: {test_dn})")
                        # Success! Now fetch groups for RBAC
                        short_username = username.split('\\')[-1]
                        search_filter = f"( |(sAMAccountName={short_username})(uid={short_username})(cn={short_username})(userPrincipalName={test_dn}))"
                        conn.search(base_dn, search_filter, attributes=['memberOf', 'distinguishedName'])

                        user_groups = []
                        if len(conn.entries) > 0:
                            user_entry = conn.entries[0]
                            if 'memberOf' in user_entry:
                                user_groups = [str(g) for g in user_entry['memberOf'].values]
                            logger.info(f"LDAP Groups for {username}: {user_groups}")

                        # --- RBAC Logic: Match LDAP groups to Profiles ---
                        profile_id = get_profile_by_ldap_groups(user_groups)

                        # Fallback to legacy admin_group check if no specific mapping found
                        if not profile_id and admin_group:
                            if any(admin_group.lower() in g.lower() for g in user_groups):
                                profile_id = 1 # Super_User

                        if not profile_id:
                            logger.warning(f"LDAP Auth success for {username} but no matching Admin Profile found for groups: {user_groups}")
                            conn.unbind()
                            return False, "Authenticated but no matching Admin Profile found for your groups.", None

                        # Get permissions for this profile
                        from .db_manager import get_admin_profiles
                        all_profiles = get_admin_profiles()
                        profile_data = next((p for p in all_profiles if p['id'] == profile_id), None)
                        import json
                        permissions = json.loads(profile_data['permissions']) if profile_data else {}

                        # --- NEW: Sync LDAP user to local users table for MFA support ---
                        try:
                            from .database.connection import db_transaction, DB_WRITE_LOCK, DB_TYPE
                            with DB_WRITE_LOCK:
                                with db_transaction() as db:
                                    if DB_TYPE == 'postgres':
                                        db.execute('''
                                            INSERT INTO users (username, password_hash, profile_id)
                                            VALUES (%s, %s, %s)
                                            ON CONFLICT (username) DO UPDATE SET profile_id = EXCLUDED.profile_id
                                        ''', (username, 'LDAP_USER', profile_id))
                                    else:
                                        db.execute('INSERT OR REPLACE INTO users (username, password_hash, profile_id) VALUES (?, ?, ?)',
                                                    (username, 'LDAP_USER', profile_id))
                        except Exception as sync_e:
                            logger.error(f"Failed to sync LDAP user to local DB: {sync_e}")
                        # --- End Sync ---

                        conn.unbind()
                        return True, "LDAP Login Successful.", {
                            "username": username,
                            "source": "ldap",
                            "profile_name": profile_data['name'] if profile_data else 'Unknown',
                            "permissions": permissions
                        }
                except Exception as bind_e:
                    logger.warning(f"LDAP bind failed for {username} with DN {test_dn}: {bind_e}")
                    last_error = str(bind_e)
                    continue

        except Exception as conn_e:
            last_error = f"Connection failed: {str(conn_e)}"

    return False, f"LDAP Auth Failed: {last_error}", None

def check_credentials(username, password):
    """
    Checks credentials against local users (DB) and configured LDAP.
    Returns: (bool, message, info_dict)
    """
    logger.info(f"Login attempt for user: {username}")
    # 1. Check Local DB (Admin + Other Local Users)
    if local_user_exists(username):
        if verify_local_user(username, password):
            perms = get_user_permissions(username)
            logger.info(f"Local login successful for user: {username}")
            return True, "Local login successful.", {"username": username, "source": "local", "permissions": perms}
        else:
            logger.warning(f"Local login failed (Invalid Password) for user: {username}")
            return False, "Invalid credentials.", None

    # 2. Check LDAP if enabled
    logger.info(f"User {username} not found locally, falling back to LDAP.")
    return _check_ldap_credentials(username, password)
