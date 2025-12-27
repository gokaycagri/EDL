import os
import json
import logging
import ssl
from ldap3 import Server, Connection, ALL, NTLM, SIMPLE, Tls

from .db_manager import (
    check_admin_credentials, 
    set_admin_password, 
    verify_local_user, 
    get_profile_by_ldap_groups,
    get_user_permissions
)

logger = logging.getLogger(__name__)

from functools import wraps
from flask import session, abort, flash, redirect, url_for

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

def check_credentials(username, password):
    """
    Checks credentials against local users (DB) and configured LDAP.
    Returns: (bool, message, info_dict)
    """
    # 1. Check Local DB (Admin + Other Local Users)
    if verify_local_user(username, password):
        perms = get_user_permissions(username)
        return True, "Local login successful.", {"username": username, "source": "local", "permissions": perms}

    # 2. Check LDAP if enabled
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
                try:
                    conn = Connection(server, user=test_dn, password=password, auto_bind=True)
                    if conn.bound:
                        # Success! Now fetch groups for RBAC
                        search_filter = f"( |(sAMAccountName={username.split('\\')[-1]})(uid={username.split('\\')[-1]})(cn={username.split('\\')[-1]})(userPrincipalName={test_dn}))"
                        conn.search(base_dn, search_filter, attributes=['memberOf', 'distinguishedName'])
                        
                        user_groups = []
                        if len(conn.entries) > 0:
                            user_entry = conn.entries[0]
                            if 'memberOf' in user_entry:
                                user_groups = [str(g) for g in user_entry['memberOf'].values]
                        
                        # --- RBAC Logic: Match LDAP groups to Profiles ---
                        profile_id = get_profile_by_ldap_groups(user_groups)
                        
                        # Fallback to legacy admin_group check if no specific mapping found
                        if not profile_id and admin_group:
                            if any(admin_group.lower() in g.lower() for g in user_groups):
                                profile_id = 1 # Super_User
                        
                        if not profile_id:
                            conn.unbind()
                            return False, "Authenticated but no matching Admin Profile found for your groups.", None

                        # Get permissions for this profile
                        from .db_manager import get_admin_profiles
                        all_profiles = get_admin_profiles()
                        profile_data = next((p for p in all_profiles if p['id'] == profile_id), None)
                        import json
                        permissions = json.loads(profile_data['permissions']) if profile_data else {}

                        conn.unbind()
                        return True, "LDAP Login Successful.", {
                            "username": username, 
                            "source": "ldap", 
                            "profile_name": profile_data['name'] if profile_data else 'Unknown',
                            "permissions": permissions
                        }
                except Exception as bind_e:
                    last_error = str(bind_e)
                    continue

        except Exception as conn_e:
            last_error = f"Connection failed: {str(conn_e)}"

    return False, f"LDAP Auth Failed: {last_error}", None
