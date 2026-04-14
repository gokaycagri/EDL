import re
import threading

from flask import flash, redirect, render_template, request, session, url_for

from ..aggregator import fetch_and_process_single_feed
from ..auth_manager import permission_required
from ..cert_manager import process_pfx_upload, process_root_ca_upload
from ..config_manager import read_config, write_config
from ..db_manager import (
    add_admin_profile,
    add_api_blacklist_item,
    add_ldap_group_mapping,
    add_local_user,
    add_whitelist_item,
    check_admin_credentials,
    create_custom_list,
    delete_admin_profile,
    delete_custom_list,
    delete_ldap_group_mapping,
    delete_local_user,
    delete_indicators,
    delete_whitelisted_indicators,
    get_admin_profiles,
    get_api_blacklist_item_by_value,
    get_all_users,
    get_ldap_group_mappings,
    is_mfa_enabled,
    remove_api_blacklist_item,
    remove_whitelist_item,
    set_admin_password,
    update_admin_profile,
    update_api_blacklist_item,
    update_local_user_password,
    update_whitelist_item,
)
from ..response_helpers import api_error, api_response
from . import bp_system
from .auth import login_required


def _parse_bulk_indicator_input(raw_items):
    """Parse user input into a unique indicator list while preserving order."""
    if not raw_items:
        return []

    candidates = re.split(r"[\s,;]+", raw_items)
    parsed = []
    seen = set()
    for candidate in candidates:
        item = candidate.strip()
        if not item or item in seen:
            continue
        seen.add(item)
        parsed.append(item)
    return parsed


@bp_system.route('/custom_lists/add', methods=['POST'])
@login_required
@permission_required('system', 'rw')
def add_custom_list_route():
    name = request.form.get('name')
    data_format = request.form.get('format', 'text')

    # Types and Sources come as comma-separated or list from form
    # If using checkboxes with same name:
    sources = request.form.getlist('sources')

    # If types are sent as comma separated string "ip,domain" or array
    types_input = request.form.get('types') # If hidden input
    if not types_input:
        # Check for radio button selection
        content_type = request.form.get('content_type')
        types = []
        if content_type == 'ip':
            types.extend(['ip', 'cidr'])
        elif content_type == 'domain':
            types.append('domain')
        elif content_type == 'url':
            types.append('url')
        else:
            # Fallback for API or legacy calls
            if request.form.get('type_ip'):
                types.extend(['ip', 'cidr'])
            if request.form.get('type_domain'):
                types.append('domain')
            if request.form.get('type_url'):
                types.append('url')
    else:
        types = types_input.split(',')

    if not name:
        flash('List Name is required.', 'danger')
        return redirect(url_for('dashboard.index'))

    if not sources:
        flash('At least one source must be selected.', 'danger')
        return redirect(url_for('dashboard.index'))

    try:
        _, token = create_custom_list(name, sources, types, data_format)
        flash(f'Custom EDL "{name}" created successfully.', 'success')
    except Exception as e:
        flash(f'Error creating list: {str(e)}', 'danger')

    return redirect(url_for('dashboard.index'))

@bp_system.route('/custom_lists/delete', methods=['POST'])
@login_required
@permission_required('system', 'rw')
def remove_custom_list_route():
    list_id = request.form.get('list_id', type=int)
    if list_id:
        if delete_custom_list(list_id):
            flash('Custom EDL deleted successfully.', 'success')
        else:
            flash('Error deleting Custom EDL.', 'danger')
    return redirect(url_for('dashboard.index'))


@bp_system.route('/')
@login_required
def index():
    from ..services.feed_health import get_all_health_statuses
    config = read_config()
    users = get_all_users()
    profiles = get_admin_profiles()
    ldap_mappings = get_ldap_group_mappings()
    user_mfa_status = is_mfa_enabled(session.get('username'))
    feed_health = get_all_health_statuses()
    return render_template('system.html', config=config, users=users, profiles=profiles, ldap_mappings=ldap_mappings, mfa_enabled=user_mfa_status, feed_health=feed_health)

@bp_system.route('/feed_health/reenable', methods=['POST'])
@login_required
@permission_required('system', 'rw')
def reenable_feed():
    from ..services.feed_health import reenable_source
    source_name = request.form.get('source_name')
    if source_name:
        reenable_source(source_name)
        flash(f'Feed "{source_name}" re-enabled.', 'success')
    return redirect(url_for('system.index'))

@bp_system.route('/ldap/mappings/add', methods=['POST'])
@login_required
@permission_required('system', 'rw')
def add_ldap_mapping():
    import logging
    logger = logging.getLogger(__name__)

    group_dn = request.form.get('group_dn')
    profile_id = request.form.get('profile_id', type=int)

    logger.info(f"Attempting to add LDAP mapping - Group: {group_dn}, Profile ID: {profile_id}")

    if group_dn and profile_id:
        success, message = add_ldap_group_mapping(group_dn, profile_id)
        if success:
            logger.info("LDAP mapping added successfully.")
            flash('LDAP Mapping added successfully.', 'success')
        else:
            logger.error(f"Failed to add LDAP mapping: {message}")
            flash(f'Error adding mapping: {message}', 'danger')
    else:
        logger.warning("Missing group_dn or profile_id in form data.")
        flash('Missing required fields.', 'danger')

    return redirect(url_for('system.index'))

@bp_system.route('/ldap/mappings/delete', methods=['POST'])
@login_required
@permission_required('system', 'rw')
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
@permission_required('system', 'rw')
def add_user():
    from ..utils import validate_password_strength
    username = request.form.get('username')
    password = request.form.get('password')
    profile_id = request.form.get('profile_id', type=int)

    if username and password:
        valid, pw_msg = validate_password_strength(password)
        if not valid:
            flash(pw_msg, 'danger')
            return redirect(url_for('system.index'))
        success, message = add_local_user(username, password, profile_id)
        if success:
            from ..services.audit_service import log_action
            log_action(session.get('username'), 'user_create', target=username)
            flash(f'User {username} added successfully.', 'success')
        else:
            flash(f'Error adding user: {message}', 'danger')
    else:
        flash('Username and password are required.', 'danger')

    return redirect(url_for('system.index'))

@bp_system.route('/admin_profiles/add', methods=['POST'])
@login_required
@permission_required('system', 'rw')
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
@permission_required('system', 'rw')
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
@permission_required('system', 'rw')
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
@permission_required('system', 'rw')
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
@permission_required('system', 'rw')
def change_user_password():
    from ..utils import validate_password_strength
    username = request.form.get('username')
    password = request.form.get('password')

    if username and password:
        valid, pw_msg = validate_password_strength(password)
        if not valid:
            flash(pw_msg, 'danger')
            return redirect(url_for('system.index'))

        success, message = update_local_user_password(username, password)
        if success:
            flash(f'Password for {username} updated successfully.', 'success')
        else:
            flash(f'Error updating password: {message}', 'danger')

    return redirect(url_for('system.index'))

def _parse_import_file(file):
    """
    Parses uploaded file (txt, json, xml) and returns unique items set.
    """
    import json

    import defusedxml.ElementTree as ET

    filename = file.filename.lower()
    content = file.read().decode('utf-8', errors='ignore')
    items = set()

    try:
        if filename.endswith('.json'):
            data = json.loads(content)
            if isinstance(data, list):
                for entry in data:
                    if isinstance(entry, str):
                        items.add(entry)
                    elif isinstance(entry, dict):
                        # Extract from common keys
                        for key in ['item', 'value', 'ip', 'domain', 'url', 'indicator']:
                            if key in entry:
                                items.add(str(entry[key]))
                                break
            elif isinstance(data, dict):
                 # Try to find a list in the dict
                 for value in data.values():
                     if isinstance(value, list):
                         for entry in value:
                             if isinstance(entry, str):
                                 items.add(entry)
        elif filename.endswith('.xml'):
            root = ET.fromstring(content)
            # Iterate all elements, check for specific tags or just text
            for elem in root.iter():
                # Filter for likely tags to avoid extracting metadata
                if elem.tag.lower() in ['item', 'value', 'ip', 'domain', 'url', 'indicator', 'host'] and elem.text:
                     items.add(elem.text.strip())
        else:
            # Default to text (one per line)
            for line in content.splitlines():
                line = line.strip()
                if line and not line.startswith('#'):
                    # Remove comments if inline? No, simple strip for now
                    items.add(line.split()[0] if ' ' in line else line)
    except Exception as e:
        return None, str(e)

    return list(items), None

@bp_system.route('/whitelist/import', methods=['POST'])
@login_required
def import_whitelist():
    if 'import_file' not in request.files:
        flash('No file part', 'danger')
        return redirect(url_for('dashboard.index'))

    file = request.files['import_file']
    if file.filename == '':
        flash('No selected file', 'danger')
        return redirect(url_for('dashboard.index'))

    items, error = _parse_import_file(file)
    if error:
        flash(f'Error parsing file: {error}', 'danger')
        return redirect(url_for('dashboard.index'))

    from ..utils import validate_indicator

    count = 0
    errors = 0
    added_items = []

    for item in items:
        is_valid, _ = validate_indicator(item)
        if is_valid:
            success, _ = add_whitelist_item(item, f"Imported from {file.filename}")
            if success:
                count += 1
                added_items.append(item)
        else:
            errors += 1

    if added_items:
        delete_whitelisted_indicators(added_items)
        flash(f'Successfully imported {count} items to Safe List. ({errors} skipped/invalid)', 'success')
    else:
        flash(f'No valid items imported. ({errors} skipped/invalid)', 'warning')

    return redirect(url_for('dashboard.index'))

@bp_system.route('/blacklist/import', methods=['POST'])
@login_required
def import_blacklist():
    if 'import_file' not in request.files:
        flash('No file part', 'danger')
        return redirect(url_for('dashboard.index'))

    file = request.files['import_file']
    if file.filename == '':
        flash('No selected file', 'danger')
        return redirect(url_for('dashboard.index'))

    items, error = _parse_import_file(file)
    if error:
        flash(f'Error parsing file: {error}', 'danger')
        return redirect(url_for('dashboard.index'))

    from ..utils import validate_indicator

    count = 0
    errors = 0

    for item in items:
        is_valid, inferred_type = validate_indicator(item)
        if is_valid:
            item_type = inferred_type if inferred_type != 'unknown' else 'ip'
            success, _ = add_api_blacklist_item(item, item_type=item_type, comment=f"Imported from {file.filename}")
            if success:
                count += 1
        else:
            errors += 1

    if count > 0:
        # Trigger regeneration
        from ..aggregator import regenerate_edl_files
        regenerate_edl_files()
        flash(f'Successfully imported {count} items to Block List. ({errors} skipped/invalid)', 'success')
    else:
        flash(f'No valid items imported. ({errors} skipped/invalid)', 'warning')

    return redirect(url_for('dashboard.index'))

@bp_system.route('/add_source', methods=['POST'])
@login_required
@permission_required('system', 'rw')
def add_source():
    # Note: In app.py this was /add
    name = request.form.get('name')
    url = request.form.get('url')
    data_format = request.form.get('format', 'text')
    key_or_column = request.form.get('key_or_column')
    auth_user = request.form.get('auth_user')
    auth_pass = request.form.get('auth_pass')
    schedule_interval_minutes = request.form.get('schedule_interval_minutes', type=int)
    confidence = request.form.get('confidence', default=50, type=int)
    retention_days = request.form.get('retention_days', type=int)

    if name and url:
        config = read_config()

        # Check for duplicate URL
        for existing_source in config.get("source_urls", []):
            if existing_source.get("url") == url:
                flash(f'Error: The URL "{url}" is already configured for source "{existing_source.get("name")}".', 'danger')
                return redirect(url_for('dashboard.index'))

        new_source = {
            "name": name,
            "url": url,
            "format": data_format,
            "confidence": confidence
        }
        if key_or_column:
            new_source["key_or_column"] = key_or_column
        if auth_user:
            new_source["auth_user"] = auth_user
        if auth_pass:
            new_source["auth_pass"] = auth_pass
        if schedule_interval_minutes:
            new_source["schedule_interval_minutes"] = schedule_interval_minutes
        if retention_days:
            new_source["retention_days"] = retention_days

        config["source_urls"].append(new_source)
        write_config(config)

        from ..scheduler_manager import update_scheduled_jobs
        update_scheduled_jobs()

    return redirect(url_for('dashboard.index'))

@bp_system.route('/update_source/<int:index>', methods=['POST'])
@login_required
@permission_required('system', 'rw')
def update_source(index):
    # Note: In app.py this was /update/<int:index>
    name = request.form.get('name')
    url = request.form.get('url')
    data_format = request.form.get('format', 'text')
    key_or_column = request.form.get('key_or_column')
    auth_user = request.form.get('auth_user')
    auth_pass = request.form.get('auth_pass')
    schedule_interval_minutes = request.form.get('schedule_interval_minutes', type=int)
    confidence = request.form.get('confidence', default=50, type=int)
    retention_days = request.form.get('retention_days', type=int)

    if name and url:
        config = read_config()
        if 0 <= index < len(config["source_urls"]):
            updated_source = {
                "name": name,
                "url": url,
                "format": data_format,
                "confidence": confidence
            }
            if key_or_column:
                updated_source["key_or_column"] = key_or_column
            if auth_user:
                updated_source["auth_user"] = auth_user
            if auth_pass:
                updated_source["auth_pass"] = auth_pass
            if schedule_interval_minutes:
                updated_source["schedule_interval_minutes"] = schedule_interval_minutes
            if retention_days:
                updated_source["retention_days"] = retention_days

            config["source_urls"][index] = updated_source
            write_config(config)

            from ..scheduler_manager import update_scheduled_jobs
            update_scheduled_jobs()

            thread = threading.Thread(target=fetch_and_process_single_feed, args=(updated_source,))
            thread.start()

    return redirect(url_for('dashboard.index'))

@bp_system.route('/remove_source/<int:index>', methods=['POST'])
@login_required
@permission_required('system', 'rw')
def remove_source(index):
    # Note: In app.py this was /remove/<int:index>
    config = read_config()
    if 0 <= index < len(config["source_urls"]):
        config["source_urls"].pop(index)
        write_config(config)

        from ..scheduler_manager import update_scheduled_jobs
        update_scheduled_jobs()

    return redirect(url_for('dashboard.index'))

@bp_system.route('/update_settings', methods=['POST'])
@login_required
@permission_required('system', 'rw')
def update_settings():
    lifetime = request.form.get('indicator_lifetime_days')
    timezone = request.form.get('timezone')
    base_url = request.form.get('base_url')

    config = read_config()
    if lifetime:
        config['indicator_lifetime_days'] = int(lifetime)
    if timezone:
        config['timezone'] = timezone
    if base_url is not None:
        # Ensure it ends with /
        base_url = base_url.strip()
        if base_url and not base_url.endswith('/'):
            base_url += '/'
        config['base_url'] = base_url

    write_config(config)
    flash('Global settings updated successfully.', 'success')
    return redirect(url_for('system.index'))

@bp_system.route('/api_client/add', methods=['POST'])
@login_required
@permission_required('system', 'rw')
def add_api_client():
    from datetime import datetime
    import secrets
    import string
    import uuid

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
@permission_required('system', 'rw')
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
@permission_required('system', 'rw')
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
@permission_required('system', 'rw')
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
        if not server:
            continue  # Skip empty

        ldap_servers_config.append({
            'server': server,
            'port': port,
            'domain': domain,
            'admin_group': group,
            'ldaps_enabled': is_ldaps
        })

    config = read_config()
    if 'auth' not in config:
        config['auth'] = {}

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
        return api_response({"ldap_status": "disabled"}, message="LDAP is disabled")

    if not servers_list:
        return api_error("No servers configured", "LDAP_NOT_CONFIGURED", 400)

    # Try to connect to at least one server
    connected = False
    details = []

    for srv in servers_list:
        host = srv.get('server')
        port = srv.get('port', 389)

        if not host:
            continue

        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(2)
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
        return api_response({"ldap_status": "online", "details": details}, message="Servers Reachable")
    else:
        return api_response({"ldap_status": "offline", "details": details}, message="Servers Unreachable")

@bp_system.route('/ldap/test', methods=['POST'])
@login_required
def test_ldap_connection():
    import logging

    from ..auth_manager import check_credentials
    logger = logging.getLogger(__name__)

    data = request.get_json()
    username = data.get('username')
    password = data.get('password')

    # Check if we have override config in the request
    # Expected format from frontend if we update it:
    # { username, password, servers: [{server, port, ...}], enabled: true }
    servers_override = data.get('servers')

    if not username or not password:
        return api_error("Username and password required.", "VALIDATION_ERROR", 400)

    logger.info(f"LDAP Test initiated for user: {username}")

    from ..auth_manager import _check_ldap_credentials
    success, message, _ = _check_ldap_credentials(username, password)

    if success:
        logger.info(f"LDAP Test SUCCESS for user: {username}")
        return api_response(message=f"Success: {message}")
    else:
        logger.warning(f"LDAP Test FAILED for user {username}: {message}")
        return api_error(f"Failed: {message}", "LDAP_AUTH_FAILED", 401)

@bp_system.route('/proxy/status', methods=['GET'])
@login_required
def check_proxy_status():
    """
    Checks if the configured Proxy is working by connecting to a site.
    """
    import requests

    from ..utils import get_proxy_settings

    proxies, _, _ = get_proxy_settings()

    if not proxies:
        return api_response({"proxy_status": "disabled"}, message="Proxy Disabled or Incomplete")

    try:
        test_url = "https://www.google.com"
        response = requests.get(test_url, proxies=proxies, timeout=5)

        if response.status_code == 200:
            return api_response({"proxy_status": "online"}, message="Proxy Working")
        else:
            return api_response({"proxy_status": "offline"}, message=f"HTTP {response.status_code}")

    except Exception as e:
        return api_response({"proxy_status": "offline"}, message=f"Connection Failed: {str(e)}")

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
        return api_response({"dns_status": "disabled"}, message="No Custom DNS Configured")

    servers_to_test = []
    if primary:
        servers_to_test.append(primary)
    if secondary:
        servers_to_test.append(secondary)

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
        detail_msg = f"Working: {', '.join(working_servers)}"
        if failed_servers:
            detail_msg += f"\nFailed: {', '.join(failed_servers)}"
        return api_response({"dns_status": "online", "details": detail_msg}, message="DNS Resolution OK")
    else:
        return api_response(
            {"dns_status": "offline", "details": f"All failed: {', '.join(failed_servers)}"},
            message="DNS Resolution Failed"
        )

@bp_system.route('/proxy/test', methods=['POST'])
@login_required
def test_proxy_connection():
    import logging
    import urllib.parse

    import requests

    logger = logging.getLogger(__name__)

    data = request.get_json()
    enabled = data.get('enabled', False)
    server = data.get('server')
    port = data.get('port')
    username = data.get('username')
    password = data.get('password')

    if not enabled:
        return api_error("Proxy is disabled. Please enable it to test.", "PROXY_DISABLED", 400)

    if not server or not port:
        return api_error("Server and Port are required.", "VALIDATION_ERROR", 400)

    # Clean server address
    server = server.replace('http://', '').replace('https://', '').strip('/')

    # URL-encode credentials for the proxy URL
    encoded_user = urllib.parse.quote(username) if username else ""
    encoded_pass = urllib.parse.quote(password) if password else ""

    auth_string = ""
    if encoded_user and encoded_pass:
        auth_string = f"{encoded_user}:{encoded_pass}@"

    proxy_url = f"http://{auth_string}{server}:{port}"
    proxies = {"http": proxy_url, "https": proxy_url}

    # Standard Browser User-Agent
    headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
    }

    try:
        # Use a session for more consistent behavior
        session = requests.Session()
        session.proxies = proxies
        session.headers.update(headers)

        # Test 1: Simple HTTP (Bypasses HTTPS Tunneling issues)
        test_url_http = "http://www.google.com"
        try:
            resp_http = session.get(test_url_http, timeout=10)
            if resp_http.status_code < 400:
                return api_response({"proxy_status": "online"}, message="Success! Connected via Proxy (HTTP).")
        except Exception as e_http:
            # If HTTP fails, we continue to try HTTPS or report the error
            logger.warning(f"Proxy HTTP Test failed: {e_http}")

        # Test 2: HTTPS (Standard)
        test_url_https = "https://www.google.com"
        response = session.get(test_url_https, timeout=10, verify=True)

        if response.status_code == 200:
            return api_response({"proxy_status": "online"}, message=f"Successfully connected to {test_url_https} via proxy.")
        else:
            return api_error(f"Proxy connected but returned status code: {response.status_code}", "PROXY_HTTP_ERROR", 502)

    except Exception as e:
        err_msg = str(e)
        if "407" in err_msg:
            err_msg += " | Hint: Check if username needs DOMAIN\\ prefix or if password has unsupported characters."
        return api_error(f"Connection failed: {err_msg}", "PROXY_CONNECTION_FAILED", 502)

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
    item_type = request.form.get('type', 'ip')
    description = request.form.get('description')

    if item:
        from ..utils import validate_indicator
        is_valid, inferred_type = validate_indicator(item)

        if not is_valid:
            flash(f'Error: "{item}" is not a valid IP, CIDR, or Domain/URL.', 'danger')
            return redirect(url_for('dashboard.index'))

        if inferred_type and inferred_type != 'unknown':
            item_type = inferred_type

        success, message = add_whitelist_item(item, item_type, description)
        if not success:
            flash(f'Error: {message}', 'danger')
        else:
            flash(f'Success: {item} added to safe list.', 'success')
            delete_whitelisted_indicators([item])

    return redirect(url_for('dashboard.index'))

@bp_system.route('/whitelist/remove/<int:item_id>', methods=['POST'])
@login_required
def remove_whitelist(item_id):
    # Note: In app.py this was /remove_whitelist/<int:item_id>
    remove_whitelist_item(item_id)
    return redirect(url_for('dashboard.index'))

@bp_system.route('/whitelist/update', methods=['POST'])
@login_required
def update_whitelist():
    item_id = request.form.get('id', type=int)
    item = request.form.get('item')
    item_type = request.form.get('type', 'ip')
    description = request.form.get('description')

    if item_id and item:
        success, message = update_whitelist_item(item_id, item, item_type, description)
        if success:
            flash('Safe List item updated successfully.', 'success')
            # Trigger cleanup for the new item if it was added to DB
            delete_whitelisted_indicators([item])
        else:
            flash(f'Error updating item: {message}', 'danger')
    else:
        flash('Invalid data for update.', 'danger')

    return redirect(url_for('dashboard.index'))

@bp_system.route('/blacklist/add', methods=['POST'])
@login_required
def add_blacklist():
    item = request.form.get('item')
    comment = request.form.get('comment', '')
    item_type = request.form.get('type', 'ip')

    if item:
        from ..utils import validate_indicator
        is_valid, inferred_type = validate_indicator(item)

        if not is_valid:
            flash(f'Error: "{item}" is not a valid IP, CIDR, or Domain/URL.', 'danger')
            return redirect(url_for('dashboard.index'))

        if inferred_type and inferred_type != 'unknown':
             item_type = inferred_type

        success, message = add_api_blacklist_item(item, item_type=item_type, comment=comment)
        if not success:
            flash(f'Error: {message}', 'danger')
        else:
            flash(f'Success: {item} added to block list.', 'success')
            # Trigger regeneration to include the new blacklist item immediately
            from ..aggregator import regenerate_edl_files
            regenerate_edl_files()

    return redirect(url_for('dashboard.index'))

@bp_system.route('/blacklist/remove/<path:item_val>', methods=['POST'])
@login_required
def remove_blacklist(item_val):
    remove_api_blacklist_item(item_val)
    # Trigger regeneration to remove the item immediately
    from ..aggregator import regenerate_edl_files
    regenerate_edl_files()
    return redirect(url_for('dashboard.index'))

@bp_system.route('/blacklist/update', methods=['POST'])
@login_required
def update_blacklist():
    item_id = request.form.get('id', type=int)
    item = request.form.get('item')
    comment = request.form.get('comment')
    item_type = request.form.get('type', 'ip')

    if item_id and item:
        success, message = update_api_blacklist_item(item_id, item, item_type, comment)
        if success:
            flash('Block List item updated successfully.', 'success')
            from ..aggregator import regenerate_edl_files
            regenerate_edl_files()
        else:
            flash(f'Error updating item: {message}', 'danger')
    else:
        flash('Invalid data for update.', 'danger')

    return redirect(url_for('dashboard.index'))


@bp_system.route('/indicators/bulk_delete', methods=['POST'])
@login_required
@permission_required('system', 'rw')
def bulk_delete_indicators_route():
    """Bulk-delete indicators from DB, optionally from block list too."""
    raw_items = request.form.get('items', '')
    remove_from_blocklist = request.form.get('remove_from_blocklist') == 'on'

    items = _parse_bulk_indicator_input(raw_items)
    if not items:
        flash('No indicators provided for deletion.', 'warning')
        return redirect(url_for('dashboard.index'))

    from ..utils import validate_indicator

    valid_items = []
    invalid_count = 0
    for item in items:
        is_valid, _ = validate_indicator(item)
        if is_valid:
            valid_items.append(item)
        else:
            invalid_count += 1

    if not valid_items:
        flash('No valid indicators found in the input.', 'danger')
        return redirect(url_for('dashboard.index'))

    deleted_from_db = delete_indicators(valid_items)
    deleted_from_blocklist = 0

    if remove_from_blocklist:
        for item in valid_items:
            if get_api_blacklist_item_by_value(item) and remove_api_blacklist_item(item):
                deleted_from_blocklist += 1

    if deleted_from_db > 0 or deleted_from_blocklist > 0:
        from ..aggregator import regenerate_edl_files

        regenerate_edl_files()

    message = f"Deleted {deleted_from_db} indicators from database"
    if remove_from_blocklist:
        message += f", removed {deleted_from_blocklist} from block list"
    if invalid_count:
        message += f". Skipped {invalid_count} invalid entries"
    message += "."

    flash(message, 'success' if (deleted_from_db > 0 or deleted_from_blocklist > 0) else 'warning')
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
