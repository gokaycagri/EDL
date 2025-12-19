import os
import json
import logging
import ssl
from ldap3 import Server, Connection, ALL, NTLM, SIMPLE, Tls

from .db_manager import check_admin_credentials, set_admin_password

logger = logging.getLogger(__name__)

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
CONFIG_FILE = os.path.join(BASE_DIR, "threat_feed_aggregator", "config", "config.json")

# Initialize admin password from ENV if DB is empty
initial_admin_password = os.environ.get('ADMIN_PASSWORD')
if initial_admin_password and not check_admin_credentials(initial_admin_password):
    success, msg = set_admin_password(initial_admin_password)
    if success:
        logger.info("Admin password initialized from ADMIN_PASSWORD environment variable.")
    else:
        logger.error(f"Failed to set initial admin password from ENV: {msg}")

def read_config():
    if not os.path.exists(CONFIG_FILE):
        return {}
    with open(CONFIG_FILE, "r") as f:
        try:
            return json.load(f)
        except json.JSONDecodeError:
            return {}

def check_credentials(username, password):
    """
    Checks credentials against local admin (from DB) and configured LDAP.
    Returns: (bool, message)
    """
    # 1. Check Local Admin (from DB)
    if username == 'admin':
        if check_admin_credentials(password):
            return True, "Local admin login successful."
        else:
            return False, "Invalid admin password."

    # 2. Check LDAP if enabled
    config = read_config()
    ldap_config = config.get('auth', {}).get('ldap', {})
    ldap_enabled = ldap_config.get('enabled', False)
            
    if ldap_enabled:
        server_hostname = ldap_config.get('server')
        base_dn = ldap_config.get('domain')
        ldaps_enabled = ldap_config.get('ldaps_enabled', False)
        ldap_cert_path = ldap_config.get('ldap_cert_path', '')
        ldap_cert_validate = ldap_config.get('ldap_cert_validate', False)

        if not server_hostname or not base_dn:
            logger.warning("LDAP enabled but server hostname or Base DN is not configured.")
            return False, "LDAP not fully configured."
        
        try:
            tls_config = None
            if ldaps_enabled:
                if ldap_cert_validate and ldap_cert_path:
                    tls_config = Tls(validate=ssl.CERT_REQUIRED, ca_certs_file=ldap_cert_path)
                else:
                    tls_config = Tls(validate=ssl.CERT_NONE)

            server = Server(server_hostname, get_info=ALL, use_ssl=ldaps_enabled, tls=tls_config)
            
            if "@" in username: # User principal name (UPN)
                user_dn = username
            else: # For OpenLDAP, users are typically under ou=people
                user_dn = f"uid={username},ou=people,{base_dn}"
            
            logger.debug(f"Attempting LDAP connection to {server_hostname} with user DN: {user_dn}")
            
            conn = Connection(server, user=user_dn, password=password, auto_bind=True)
            
            if conn.bound:
                conn.unbind()
                logger.info(f"LDAP login successful for user: {username}")
                return True, "LDAP login successful."
            else:
                logger.warning(f"LDAP bind failed for user: {username}. Error: {conn.result}")
                return False, "Invalid LDAP credentials."
        except Exception as e:
            logger.error(f"LDAP authentication error for user {username}: {e}")
            return False, "LDAP authentication error."

    return False, "Invalid Credentials." # Fallback if no auth method succeeds
