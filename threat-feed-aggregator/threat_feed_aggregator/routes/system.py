from flask import render_template, request, redirect, url_for, flash
import threading
from ..config_manager import read_config, write_config
from ..db_manager import (
    add_whitelist_item,
    remove_whitelist_item,
    delete_whitelisted_indicators,
    check_admin_credentials,
    set_admin_password
)
from ..cert_manager import process_pfx_upload
from ..aggregator import fetch_and_process_single_feed

from . import bp_system
from .auth import login_required

@bp_system.route('/')
@login_required
def index():
    config = read_config()
    return render_template('system.html', config=config)

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
    # Note: In app.py this was /update_ldap_settings
    server = request.form.get('ldap_server').replace('ldap://', '')
    domain = request.form.get('ldap_domain')
    admin_group = request.form.get('ldap_admin_group')
    enabled = request.form.get('ldap_enabled') == 'on'
    ldaps_enabled = request.form.get('ldaps_enabled') == 'on'
    ldap_cert_path = request.form.get('ldap_cert_path')
    ldap_cert_validate = request.form.get('ldap_cert_validate') == 'on'
    
    config = read_config()
    if 'auth' not in config: config['auth'] = {}
    
    config['auth']['ldap'] = {
        'enabled': enabled,
        'server': server,
        'domain': domain,
        'admin_group': admin_group,
        'ldaps_enabled': ldaps_enabled,
        'ldap_cert_path': ldap_cert_path,
        'ldap_cert_validate': ldap_cert_validate
    }
    
    write_config(config)
    return redirect(url_for('dashboard.index'))

@bp_system.route('/update_proxy', methods=['POST'])
@login_required
def update_proxy():
    enabled = request.form.get('proxy_enabled') == 'on'
    server = request.form.get('proxy_server')
    port = request.form.get('proxy_port')
    username = request.form.get('proxy_username')
    password = request.form.get('proxy_password')
    
    config = read_config()
    
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
