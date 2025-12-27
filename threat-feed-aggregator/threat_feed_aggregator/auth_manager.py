import os
import json
import logging
import ssl
from ldap3 import Server, Connection, ALL, NTLM, SIMPLE, Tls

from .db_manager import check_admin_credentials, set_admin_password, verify_local_user

logger = logging.getLogger(__name__)

def authenticate_ldap_user(username, password, servers_list):
    """
    Attempts to authenticate a user against a list of LDAP server configurations.
    Returns: (bool, message)
    """
    if not servers_list:
        return False, "LDAP server list is empty."

    from .cert_manager import get_ca_bundle_path
    ca_bundle = get_ca_bundle_path()
    last_error = "No LDAP servers responded."

    for srv_config in servers_list:
        server_hostname = srv_config.get('server')
        server_port = srv_config.get('port', 389)
        base_dn = srv_config.get('domain')
        admin_group = srv_config.get('admin_group')
        ldaps_enabled = srv_config.get('ldaps_enabled', False)

        if not server_hostname or not base_dn:
            continue
        
        logger.warning(f"[v1.5.1] LDAP CHECK: Trying {server_hostname}:{server_port} (SSL: {ldaps_enabled})")
        
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
                # 1. UPN (user@domain.local) derived from Base DN
                domain_parts = [p.split('=')[1] for p in base_dn.lower().split(',') if p.startswith('dc=')]
                if domain_parts:
                    domain_suffix = ".".join(domain_parts)
                    possible_dns.append(f"{username}@{domain_suffix}")
                # 2. Standard DN pattern
                possible_dns.append(f"uid={username},ou=people,{base_dn}")
                # 3. Standard Users container
                possible_dns.append(f"cn={username},cn=users,{base_dn}")

            for test_dn in possible_dns:
                logger.warning(f"[v1.5.1] LDAP BIND TRY: {test_dn}")
                try:
                    # For NTLM (DOMAIN\user), ldap3 needs specific handling sometimes, but auto_bind handles SIMPLE by default
                    conn = Connection(server, user=test_dn, password=password, auto_bind=True)
                    if conn.bound:
                        logger.warning(f"[v1.5.1] LDAP BIND SUCCESS: {test_dn}")
                        
                        if admin_group:
                            # Group membership check - Searching for user object to get memberOf
                            # Split by backslash to handle DOMAIN\user format, take the last part (username)
                            safe_username = username.split('\\')[-1]
                            search_filter = f"( |(sAMAccountName={safe_username})(uid={safe_username})(cn={safe_username})(userPrincipalName={test_dn}))"
                            conn.search(base_dn, search_filter, attributes=['memberOf', 'distinguishedName'])
                            
                            if len(conn.entries) > 0:
                                user_entry = conn.entries[0]
                                member_of = [str(g).lower() for g in user_entry['memberOf'].values]
                                logger.warning(f"[v1.5.1] User groups found: {len(member_of)}")
                                
                                if any(admin_group.lower() in g for g in member_of):
                                    logger.warning(f"[v1.5.1] LDAP GROUP OK: {username} is member of {admin_group}")
                                    conn.unbind()
                                    return True, "LDAP Login Successful."
                                else:
                                    last_error = f"User authenticated but NOT a member of required group: {admin_group}"
                                    logger.warning(f"[v1.5.1] LDAP GROUP FAIL: {username} NOT in {admin_group}")
                            else:
                                last_error = "User object found but attributes (memberOf) are unreadable."
                                logger.warning(f"[v1.5.1] LDAP ATTR FAIL: {last_error}")
                            
                            conn.unbind()
                            continue # Try next DN if group check failed for this one
                        
                        conn.unbind()
                        return True, "LDAP Login Successful."
                except Exception as bind_e:
                    last_error = str(bind_e)
                    logger.warning(f"[v1.5.1] LDAP BIND FAIL for {test_dn}: {last_error}")
                    continue

        except Exception as conn_e:
            last_error = f"Connection failed: {str(conn_e)}"
            logger.error(f"[v1.5.1] LDAPCONN ERROR: {last_error}")

    return False, f"LDAP Auth Failed: {last_error}"

def check_credentials(username, password):
    """
    Checks credentials against local users (DB) and configured LDAP.
    Returns: (bool, message)
    """
    # 1. Check Local DB (Admin + Other Local Users)
    if verify_local_user(username, password):
        return True, "Local login successful."

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
        return False, "LDAP authentication is disabled."

    return authenticate_ldap_user(username, password, servers_list)
