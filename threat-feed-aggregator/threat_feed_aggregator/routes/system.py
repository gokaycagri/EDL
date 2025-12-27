from flask import render_template, request, redirect, url_for, flash, jsonify
import threading
from ..config_manager import read_config, write_config
from ..db_manager import (
    add_whitelist_item,
    remove_whitelist_item,
    delete_whitelisted_indicators,
    check_admin_credentials,
    set_admin_password,
    get_all_users,
    add_local_user,
    delete_local_user,
    update_local_user_password,
    get_admin_profiles,
    add_admin_profile,
    update_admin_profile,
    delete_admin_profile,
    get_ldap_group_mappings,
    add_ldap_group_mapping,
    delete_ldap_group_mapping
)
from ..cert_manager import process_pfx_upload, process_root_ca_upload
from ..aggregator import fetch_and_process_single_feed

from . import bp_system
from .auth import login_required

@bp_system.route('/')
@login_required
def index():
    config = read_config()
    users = get_all_users()
    profiles = get_admin_profiles()
    ldap_mappings = get_ldap_group_mappings()
    return render_template('system.html', config=config, users=users, profiles=profiles, ldap_mappings=ldap_mappings)

@bp_system.route('/ldap/mappings/add', methods=['POST'])
@login_required
def add_ldap_mapping():
    group_dn = request.form.get('group_dn')
    profile_id = request.form.get('profile_id', type=int)
    
    if group_dn and profile_id:
        success, message = add_ldap_group_mapping(group_dn, profile_id)
        if success:
            flash('LDAP Mapping added successfully.', 'success')
        else:
            flash(f'Error adding mapping: {message}', 'danger')
            
    return redirect(url_for('system.index'))

@bp_system.route('/ldap/mappings/delete', methods=['POST'])
@login_required
def delete_ldap_mapping():
    mapping_id = request.form.get('mapping_id', type=int)
    
    if mapping_id:
        success, message = delete_ldap_group_mapping(mapping_id)
        if success:
            flash('Mapping deleted successfully.', 'success')
        else:
            flash(f'Error deleting mapping: {message}', 'danger')
            
    return redirect(url_for('system.index'))

@bp_system.route('/users/add', methods=['POST'])
@login_required
def add_user():
    username = request.form.get('username')
    password = request.form.get('password')
    profile_id = request.form.get('profile_id', type=int)
    
    if username and password:
        success, message = add_local_user(username, password, profile_id)
        if success:
            flash(f'User {username} added successfully.', 'success')
        else:
            flash(f'Error adding user: {message}', 'danger')
    else:
        flash('Username and password are required.', 'danger')
        
    return redirect(url_for('system.index'))

@bp_system.route('/admin_profiles/add', methods=['POST'])
@login_required
def add_profile():
    import json
    name = request.form.get('name')
    description = request.form.get('description')
    permissions_str = request.form.get('permissions') # JSON string from frontend
    
    if name and permissions_str:
        try:
            permissions = json.loads(permissions_str)
            success, message = add_admin_profile(name, description, permissions)
            if success:
                flash('Profile added successfully.', 'success')
            else:
                flash(f'Error adding profile: {message}', 'danger')
        except json.JSONDecodeError:
            flash('Invalid permissions format.', 'danger')
            
    return redirect(url_for('system.index'))

@bp_system.route('/admin_profiles/update', methods=['POST'])
@login_required
def update_profile():
    import json
    profile_id = request.form.get('profile_id', type=int)
    description = request.form.get('description')
    permissions_str = request.form.get('permissions')
    
    if profile_id and permissions_str:
        try:
            permissions = json.loads(permissions_str)
            success, message = update_admin_profile(profile_id, description, permissions)
            if success:
                flash('Profile updated successfully.', 'success')
            else:
                flash(f'Error updating profile: {message}', 'danger')
        except json.JSONDecodeError:
            flash('Invalid permissions format.', 'danger')
            
    return redirect(url_for('system.index'))

@bp_system.route('/admin_profiles/delete', methods=['POST'])
@login_required
def delete_profile():
    profile_id = request.form.get('profile_id', type=int)
    
    if profile_id:
        success, message = delete_admin_profile(profile_id)
        if success:
            flash('Profile deleted successfully.', 'success')
        else:
            flash(f'Error deleting profile: {message}', 'danger')
            
    return redirect(url_for('system.index'))

@bp_system.route('/users/delete', methods=['POST'])
@login_required
def delete_user():
    username = request.form.get('username')
    
    if username:
        success, message = delete_local_user(username)
        if success:
            flash(f'User {username} deleted successfully.', 'success')
        else:
            flash(f'Error deleting user: {message}', 'danger')
            
    return redirect(url_for('system.index'))

@bp_system.route('/users/change_password', methods=['POST'])
@login_required
def change_user_password():
    username = request.form.get('username')
    password = request.form.get('password')
    
    # Optional: Verify current admin password for security before changing others?
    # For now, assuming logged-in admin has rights.
    
    if username and password:
        success, message = update_local_user_password(username, password)
        if success:
            flash(f'Password for {username} updated successfully.', 'success')
        else:
            flash(f'Error updating password: {message}', 'danger')
            
    return redirect(url_for('system.index'))

@bp_system.route('/add_source', methods=['POST'])
@login_required
def add_source():
    # Note: In app.py this was /add
    name = request.form.get('name')
    url = request.form.get('url')
    data_format = request.form.get('format', 'text')
    key_or_column = request.form.get('key_or_column')
    schedule_interval_minutes = request.form.get('schedule_interval_minutes', type=int)
    confidence = request.form.get('confidence', default=50, type=int)
    retention_days = request.form.get('retention_days', type=int)
    
    collection_id = request.form.get('collection_id')
    username = request.form.get('username')
    password = request.form.get('password')
    
    if name and url:
        config = read_config()
        new_source = {
            "name": name, 
            "url": url, 
            "format": data_format,
            "confidence": confidence
        }
        if key_or_column: new_source["key_or_column"] = key_or_column
        if schedule_interval_minutes: new_source["schedule_interval_minutes"] = schedule_interval_minutes
        if retention_days: new_source["retention_days"] = retention_days
        if collection_id: new_source["collection_id"] = collection_id
        if username: new_source["username"] = username
        if password: new_source["password"] = password
            
        config["source_urls"].append(new_source)
        write_config(config)
        
        from ..app import update_scheduled_jobs
        update_scheduled_jobs()
        
    return redirect(url_for('dashboard.index'))

@bp_system.route('/update_source/<int:index>', methods=['POST'])
@login_required
def update_source(index):
    # Note: In app.py this was /update/<int:index>
    name = request.form.get('name')
    url = request.form.get('url')
    data_format = request.form.get('format', 'text')
    key_or_column = request.form.get('key_or_column')
    schedule_interval_minutes = request.form.get('schedule_interval_minutes', type=int)
    confidence = request.form.get('confidence', default=50, type=int)
    retention_days = request.form.get('retention_days', type=int)

    collection_id = request.form.get('collection_id')
    username = request.form.get('username')
    password = request.form.get('password')

    if name and url:
        config = read_config()
        if 0 <= index < len(config["source_urls"]):
            updated_source = {
                "name": name, 
                "url": url, 
                "format": data_format,
                "confidence": confidence
            }
            if key_or_column: updated_source["key_or_column"] = key_or_column
            if schedule_interval_minutes: updated_source["schedule_interval_minutes"] = schedule_interval_minutes
            if retention_days: updated_source["retention_days"] = retention_days
            if collection_id: updated_source["collection_id"] = collection_id
            if username: updated_source["username"] = username
            if password: updated_source["password"] = password

            config["source_urls"][index] = updated_source
            write_config(config)
            
            from ..app import update_scheduled_jobs
            update_scheduled_jobs()

            thread = threading.Thread(target=fetch_and_process_single_feed, args=(updated_source,))
            thread.start()

    return redirect(url_for('dashboard.index'))

@bp_system.route('/remove_source/<int:index>')
@login_required
def remove_source(index):
    # Note: In app.py this was /remove/<int:index>
    config = read_config()
    if 0 <= index < len(config["source_urls"]):
        config["source_urls"].pop(index)
        write_config(config)
        
        from ..app import update_scheduled_jobs
        update_scheduled_jobs()
        
    return redirect(url_for('dashboard.index'))

@bp_system.route('/update_settings', methods=['POST'])
@login_required
def update_settings():
    lifetime = request.form.get('indicator_lifetime_days')
    if lifetime:
        config = read_config()
        config['indicator_lifetime_days'] = int(lifetime)
        write_config(config)
    return redirect(url_for('dashboard.index'))

@bp_system.route('/api_client/add', methods=['POST'])
@login_required
def add_api_client():
    import secrets
    import string
    import uuid
    from datetime import datetime
    
    name = request.form.get('name')
    allowed_ips_str = request.form.get('allowed_ips', '')
    
    if name:
        config = read_config()
        if 'api_clients' not in config:
            config['api_clients'] = []
            
        # Parse IPs
        allowed_ips = [ip.strip() for ip in allowed_ips_str.split(',') if ip.strip()]
        
        # Generate Key
        alphabet = string.ascii_letters + string.digits
        new_key = ''.join(secrets.choice(alphabet) for i in range(32))
        
        new_client = {
            "id": str(uuid.uuid4()),
            "name": name,
            "api_key": new_key,
            "allowed_ips": allowed_ips,
            "created_at": datetime.now().isoformat()
        }
        
        config['api_clients'].append(new_client)
        write_config(config)
        flash(f'API Client "{name}" added successfully.', 'success')
            
    return redirect(url_for('system.index'))

@bp_system.route('/api_client/regenerate_key', methods=['POST'])
@login_required
def regenerate_api_client_key():
    import secrets
    import string
    
    client_id = request.form.get('client_id')
    
    if client_id:
        config = read_config()
        if 'api_clients' in config:
            for client in config['api_clients']:
                if client['id'] == client_id:
                    alphabet = string.ascii_letters + string.digits
                    new_key = ''.join(secrets.choice(alphabet) for i in range(32))
                    client['api_key'] = new_key
                    write_config(config)
                    flash(f'API Key for "{client["name"]}" regenerated successfully.', 'success')
                    break
            
    return redirect(url_for('system.index'))

@bp_system.route('/api_client/remove', methods=['POST'])
@login_required
def remove_api_client():
    client_id = request.form.get('client_id')
    
    if client_id:
        config = read_config()
        if 'api_clients' in config:
            original_len = len(config['api_clients'])
            config['api_clients'] = [c for c in config['api_clients'] if c['id'] != client_id]
            
            if len(config['api_clients']) < original_len:
                write_config(config)
                flash('API Client removed.', 'success')
            
    return redirect(url_for('system.index'))

@bp_system.route('/update_ldap', methods=['POST'])
@login_required
def update_ldap():
    enabled = request.form.get('ldap_enabled') == 'on'
    
    # Get list of servers
    servers = request.form.getlist('ldap_server[]')
    
    # Get common configuration
    port = request.form.get('ldap_port', type=int) or 389
    domain = request.form.get('ldap_domain')
    group = request.form.get('ldap_admin_group')
    is_ldaps = request.form.get('ldaps_enabled') == 'on'
    
    ldap_servers_config = []
    
    # Iterate and construct config objects
    for server in servers:
        server = server.strip().replace('ldap://', '').replace('ldaps://', '')
        if not server: continue # Skip empty
        
        ldap_servers_config.append({
            'server': server,
            'port': port,
            'domain': domain,
            'admin_group': group,
            'ldaps_enabled': is_ldaps
        })
    
    config = read_config()
    if 'auth' not in config: config['auth'] = {}
    
    config['auth']['ldap_enabled'] = enabled
    config['auth']['ldap_servers'] = ldap_servers_config
    
    # Backward compatibility: Save first server/common settings to old fields
    if ldap_servers_config:
        first = ldap_servers_config[0]
        config['auth']['ldap'] = {
            'enabled': enabled, # Keep this synced
            'server': first['server'],
            'port': first['port'],
            'domain': first['domain'],
            'admin_group': first['admin_group'],
            'ldaps_enabled': first['ldaps_enabled']
        }
    
    write_config(config)
    flash('LDAP settings updated successfully.', 'success')
    return redirect(url_for('system.index'))

@bp_system.route('/ldap/status', methods=['GET'])
@login_required
def check_ldap_server_status():
    """
    Checks if the configured LDAP servers are reachable (TCP connect).
    Does not test authentication since passwords are not stored.
    """
    import socket
    from ..config_manager import read_config
    
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
        return jsonify({'status': 'disabled', 'message': 'LDAP is disabled'})
        
    if not servers_list:
        return jsonify({'status': 'error', 'message': 'No servers configured'})

    # Try to connect to at least one server
    connected = False
    details = []
    
    for srv in servers_list:
        host = srv.get('server')
        port = srv.get('port', 389)
        
        if not host: continue
        
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(2) # 2 seconds timeout
            result = sock.connect_ex((host, int(port)))
            sock.close()
            
            if result == 0:
                connected = True
                details.append(f"{host}: OK")
            else:
                details.append(f"{host}: Unreachable")
        except Exception as e:
            details.append(f"{host}: Error ({str(e)})")
            
    if connected:
        return jsonify({'status': 'online', 'message': 'Servers Reachable', 'details': details})
    else:
        return jsonify({'status': 'offline', 'message': 'Servers Unreachable', 'details': details})

@bp_system.route('/ldap/test', methods=['POST'])
@login_required
def test_ldap_connection():
    from ..auth_manager import authenticate_ldap_user, check_credentials
    import logging
    logger = logging.getLogger(__name__)
    
    data = request.get_json()
    username = data.get('username')
    password = data.get('password')
    
    # Check if we have override config in the request
    # Expected format from frontend if we update it: 
    # { username, password, servers: [{server, port, ...}], enabled: true }
    servers_override = data.get('servers')
    
    if not username or not password:
        return jsonify({'status': 'error', 'message': 'Username and password required.'})
        
    logger.info(f"LDAP Test initiated for user: {username}")
    
    if servers_override:
        # For testing purposes, we use a temporary function or adapt auth_manager
        # For now, let's just use the logic in auth_manager
        # But auth_manager expects saved config for some parts.
        # Since this is a test, we skip RBAC check usually.
        # I'll add a helper in auth_manager or just use the logic here.
        # Actually, let's keep it simple:
        from ..auth_manager import check_credentials
        success, message, _ = check_credentials(username, password)
    else:
        success, message, _ = check_credentials(username, password)
    
    if success:
        logger.info(f"LDAP Test SUCCESS for user: {username}")
        return jsonify({'status': 'success', 'message': f'Success: {message}'})
    else:
        logger.warning(f"LDAP Test FAILED for user {username}: {message}")
        return jsonify({'status': 'error', 'message': f'Failed: {message}'})

@bp_system.route('/proxy/status', methods=['GET'])
@login_required
def check_proxy_status():
    """
    Checks if the configured Proxy is working by connecting to a site.
    """
    import requests
    from ..config_manager import read_config
    
    config = read_config()
    proxy_config = config.get('proxy', {})
    
    enabled = proxy_config.get('enabled')
    server = proxy_config.get('server')
    port = proxy_config.get('port')
    username = proxy_config.get('username')
    password = proxy_config.get('password')
    
    if not enabled:
        return jsonify({'status': 'disabled', 'message': 'Proxy Disabled'})
        
    if not server or not port:
        return jsonify({'status': 'error', 'message': 'Incomplete Configuration'})
        
    # Construct Proxy URL
    auth_string = ""
    if username and password:
        auth_string = f"{username}:{password}@"
        
    proxy_url = f"http://{auth_string}{server}:{port}"
    proxies = {"http": proxy_url, "https": proxy_url}
    
    try:
        # Test connection to a reliable external site
        test_url = "https://www.google.com"
        response = requests.get(test_url, proxies=proxies, timeout=5)
        
        if response.status_code == 200:
            return jsonify({'status': 'online', 'message': 'Proxy Working'})
        else:
            return jsonify({'status': 'offline', 'message': f'HTTP {response.status_code}'})
            
    except Exception as e:
        return jsonify({'status': 'offline', 'message': 'Connection Failed'})

@bp_system.route('/update_proxy', methods=['POST'])
@login_required
def update_proxy():
    import logging
    logger = logging.getLogger(__name__)
    logger.info("RECEIVED /update_proxy request")
    
    enabled = request.form.get('proxy_enabled') == 'on'
    server = request.form.get('proxy_server')
    port = request.form.get('proxy_port')
    username = request.form.get('proxy_username')
    password = request.form.get('proxy_password')
    
    config = read_config()
    
    if enabled and server:
        # Clean server address (remove protocol if user added it)
        server = server.replace('http://', '').replace('https://', '').strip('/')
    
    config['proxy'] = {
        'enabled': enabled,
        'server': server,
        'port': port,
        'username': username,
        'password': password
    }
    
    write_config(config)
    flash('Proxy settings updated successfully.', 'success')
    return redirect(url_for('system.index'))

@bp_system.route('/update_dns', methods=['POST'])
@login_required
def update_dns():
    import logging
    logger = logging.getLogger(__name__)
    logger.info("RECEIVED /update_dns request")
    
    primary = request.form.get('dns_primary')
    secondary = request.form.get('dns_secondary')
    
    config = read_config()
    config['dns'] = {
        'primary': primary,
        'secondary': secondary
    }
    
    write_config(config)
    flash('DNS settings updated successfully.', 'success')
    return redirect(url_for('system.index'))

@bp_system.route('/dns/status', methods=['GET'])
@login_required
def check_dns_status():
    """
    Checks if the configured DNS servers are working by resolving a domain.
    """
    import dns.resolver
    from ..config_manager import read_config
    
    config = read_config()
    dns_config = config.get('dns', {})
    
    primary = dns_config.get('primary')
    secondary = dns_config.get('secondary')
    
    if not primary and not secondary:
        return jsonify({'status': 'disabled', 'message': 'No Custom DNS Configured'})
        
    servers_to_test = []
    if primary: servers_to_test.append(primary)
    if secondary: servers_to_test.append(secondary)
    
    working_servers = []
    failed_servers = []
    
    for server in servers_to_test:
        try:
            resolver = dns.resolver.Resolver()
            resolver.nameservers = [server]
            resolver.timeout = 2
            resolver.lifetime = 2
            
            # Try to resolve a reliable domain
            resolver.resolve('google.com', 'A')
            working_servers.append(server)
        except Exception as e:
            failed_servers.append(f"{server} ({str(e)})")
            
    if working_servers:
        details = f"Working: {', '.join(working_servers)}"
        if failed_servers:
            details += f"\nFailed: {', '.join(failed_servers)}"
        return jsonify({'status': 'online', 'message': 'DNS Resolution OK', 'details': details})
    else:
        return jsonify({'status': 'offline', 'message': 'DNS Resolution Failed', 'details': f"All failed: {', '.join(failed_servers)}"})

@bp_system.route('/proxy/test', methods=['POST'])
@login_required
def test_proxy_connection():
    import requests
    
    data = request.get_json()
    enabled = data.get('enabled', False)
    server = data.get('server')
    port = data.get('port')
    username = data.get('username')
    password = data.get('password')
    
    if not enabled:
        return jsonify({'status': 'error', 'message': 'Proxy is disabled. Please enable it to test.'})
        
    if not server or not port:
        return jsonify({'status': 'error', 'message': 'Server and Port are required.'})
        
    # Clean server address (remove protocol if user added it)
    server = server.replace('http://', '').replace('https://', '').strip('/')
        
    # Construct Proxy URL
    auth_string = ""
    if username and password:
        auth_string = f"{username}:{password}@"
        
    proxy_url = f"http://{auth_string}{server}:{port}"
    proxies = {"http": proxy_url, "https": proxy_url}
    
    try:
        # Test connection to a reliable external site
        test_url = "https://www.google.com"
        response = requests.get(test_url, proxies=proxies, timeout=10)
        
        if response.status_code == 200:
            return jsonify({'status': 'success', 'message': f'Successfully connected to {test_url} via proxy.'})
        else:
            return jsonify({'status': 'error', 'message': f'Proxy connected but returned status code: {response.status_code}'})
            
    except Exception as e:
        return jsonify({'status': 'error', 'message': f'Connection failed: {str(e)}'})

@bp_system.route('/upload_cert', methods=['POST'])
@login_required
def upload_cert():
    if 'pfx_file' not in request.files:
        flash('No file part', 'danger')
        return redirect(url_for('system.index'))
    
    file = request.files['pfx_file']
    password = request.form.get('password', '')

    if file.filename == '':
        flash('No selected file', 'danger')
        return redirect(url_for('system.index'))

    if file:
        file_content = file.read()
        success, message = process_pfx_upload(file_content, password)
        if success:
            flash(f"{message} Note: You must restart the Docker container for changes to take effect.", 'success')
        else:
            flash(f"Error uploading certificate: {message}", 'danger')
            
    return redirect(url_for('system.index'))

@bp_system.route('/upload_root_ca', methods=['POST'])
@login_required
def upload_root_ca():
    if 'ca_file' not in request.files:
        flash('No file part', 'danger')
        return redirect(url_for('system.index'))
        
    file = request.files['ca_file']
    if file.filename == '':
        flash('No selected file', 'danger')
        return redirect(url_for('system.index'))
        
    if file:
        try:
            content = file.read()
            success, message = process_root_ca_upload(content)
            if success:
                flash(f"{message} Please restart the application for this to apply to all connections.", 'success')
            else:
                flash(f"Error trusting CA: {message}", 'danger')
        except Exception as e:
            flash(f"Error: {str(e)}", 'danger')
            
    return redirect(url_for('system.index'))

@bp_system.route('/whitelist/add', methods=['POST'])
@login_required
def add_whitelist():
    # Note: In app.py this was /add_whitelist
    item = request.form.get('item')
    description = request.form.get('description')
    
    if item:
        success, message = add_whitelist_item(item, description)
        if not success:
            flash(f'Error: {message}')
        else:
            delete_whitelisted_indicators([item])
            
    return redirect(url_for('dashboard.index'))

@bp_system.route('/whitelist/remove/<int:item_id>', methods=['GET'])
@login_required
def remove_whitelist(item_id):
    # Note: In app.py this was /remove_whitelist/<int:item_id>
    remove_whitelist_item(item_id)
    return redirect(url_for('dashboard.index'))

@bp_system.route('/change_password', methods=['POST'])
@login_required
def change_password():
    # Note: In app.py this was /change_admin_password
    current_password = request.form.get('current_password')
    new_password = request.form.get('new_password')
    confirm_new_password = request.form.get('confirm_new_password')

    if not check_admin_credentials(current_password):
        flash('Current password is incorrect.', 'danger')
        return redirect(url_for('dashboard.index'))
    
    if not new_password or new_password != confirm_new_password:
        flash('New passwords do not match or are empty.', 'danger')
        return redirect(url_for('dashboard.index'))
    
    success, message = set_admin_password(new_password)
    if success:
        flash('Admin password updated successfully. Please re-login with your new password.', 'success')
        session.pop('logged_in', None)
        session.pop('username', None)
        return redirect(url_for('auth.login'))
    else:
        flash(f'Error updating password: {message}', 'danger')
        return redirect(url_for('dashboard.index'))
