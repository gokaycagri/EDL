import os
import json
import logging
from ldap3 import Server, Connection, ALL, NTLM, SIMPLE

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
CONFIG_FILE = os.path.join(BASE_DIR, "threat_feed_aggregator", "config", "config.json")

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
    Checks credentials against local admin and configured LDAP.
    Returns: (bool, message)
    """
    # 1. Check Local Admin
    admin_password = os.environ.get('ADMIN_PASSWORD', '123456')
    if username == 'admin' and password == admin_password:
        return True, "Local admin login successful."

    # 2. Check LDAP if enabled
    config = read_config()
    ldap_config = config.get('auth', {}).get('ldap', {})

    if ldap_config.get('enabled'):
        server_address = ldap_config.get('server')
        domain = ldap_config.get('domain')
        
        if not server_address:
            return False, "LDAP enabled but server not configured."

        # Construct user DN or UPN based on configuration
        # Simple approach: try creating a UPN (user@domain) or Down-Level Logon Name (DOMAIN\user)
        user_dn = username
        if domain:
            # Try DOMAIN\user format commonly used in AD
            user_dn = f"{domain}\\{username}"
        
        try:
            # Configure Server (detect SSL if port 636)
            use_ssl = False
            if ':636' in server_address or 'ldaps://' in server_address:
                use_ssl = True
            
            server = Server(server_address, get_info=ALL, use_ssl=use_ssl)
            
            # Try to bind (authenticate)
            # We use auto_bind=True to attempt connection immediately
            conn = Connection(server, user=user_dn, password=password, auto_bind=True)
            
            if conn.bound:
                conn.unbind()
                return True, "LDAP login successful."
            else:
                return False, "LDAP authentication failed."
                
        except Exception as e:
            logging.error(f"LDAP Error: {e}")
            return False, f"LDAP Error: {str(e)}"

    return False, "Invalid credentials."
