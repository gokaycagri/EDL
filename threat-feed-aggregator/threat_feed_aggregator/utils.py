import ipaddress
import os
import logging

logger = logging.getLogger(__name__)

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SAFE_LIST_FILE = os.path.join(BASE_DIR, "data", "safe_list.txt")

def load_safe_list():
    """
    Loads the safe list from the file into memory.
    Returns a set of strings (IPs, Domains) and a list of ip_network objects.
    """
    safe_items = set()
    safe_networks = []
    
    if not os.path.exists(SAFE_LIST_FILE):
        return safe_items, safe_networks

    try:
        with open(SAFE_LIST_FILE, 'r') as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith('#'):
                    continue
                
                # Check if it's a CIDR
                if '/' in line:
                    try:
                        safe_networks.append(ipaddress.ip_network(line, strict=False))
                    except ValueError:
                        pass # Not a valid network, maybe a domain with slash? treat as string
                        safe_items.add(line)
                else:
                    safe_items.add(line)
    except Exception as e:
        logger.error(f"Error loading safe list: {e}")
        
    return safe_items, safe_networks

# Load safe list once on module import (or reload periodically if needed)
SAFE_ITEMS, SAFE_NETWORKS = load_safe_list()

def reload_safe_list():
    """Reloads the safe list from file into global variables."""
    global SAFE_ITEMS, SAFE_NETWORKS
    SAFE_ITEMS, SAFE_NETWORKS = load_safe_list()

def add_to_safe_list(item):
    """Adds an item to the safe list file."""
    if not item: return False, "Empty item"
    
    # Check if already exists (simple check)
    if item in SAFE_ITEMS:
        return False, "Item already in safe list"

    try:
        # Append to file
        with open(SAFE_LIST_FILE, 'a') as f:
            f.write(f"\n{item}")
        
        # Reload memory
        reload_safe_list()
        return True, "Item added to safe list"
    except Exception as e:
        logger.error(f"Error writing to safe list file: {e}")
        return False, str(e)

def remove_from_safe_list(item_to_remove):
    """Removes an item from the safe list file."""
    if not os.path.exists(SAFE_LIST_FILE):
        return False, "Safe list file not found"

    try:
        with open(SAFE_LIST_FILE, 'r') as f:
            lines = f.readlines()
        
        with open(SAFE_LIST_FILE, 'w') as f:
            found = False
            for line in lines:
                if line.strip() == item_to_remove:
                    found = True
                    continue # Skip this line
                f.write(line)
        
        if found:
            reload_safe_list()
            return True, "Item removed from safe list"
        else:
            return False, "Item not found in safe list"
            
    except Exception as e:
        logger.error(f"Error removing from safe list file: {e}")
        return False, str(e)

def is_whitelisted(indicator, whitelist_db_items=None, precomputed_db_nets=None):
    """
    Checks if an indicator is in the user-defined whitelist OR the global safe list.
    Supports IPs, CIDRs, and exact string matches for Domains.
    
    precomputed_db_nets: Optional list of ip_network objects for DB whitelist items.
    """
    # 1. Check Global Safe List (Exact Match) - O(1)
    if indicator in SAFE_ITEMS:
        return True, "Global Safe List"

    # 2. Check Global Safe List (CIDR) - Optimized
    try:
        is_cidr = '/' in indicator
        if is_cidr:
            input_obj = ipaddress.ip_network(indicator, strict=False)
            for net in SAFE_NETWORKS:
                if input_obj.subnet_of(net): return True, "Global Safe List (CIDR)"
        else:
            input_obj = ipaddress.ip_address(indicator)
            for net in SAFE_NETWORKS:
                if input_obj in net: return True, "Global Safe List (CIDR)"
    except ValueError:
        return False, None # Invalid indicator string

    # 3. Check User DB Whitelist
    if whitelist_db_items:
        # Exact match check first (O(1) if items is a set)
        if indicator in whitelist_db_items:
            return True, "User Whitelist"
        
        # CIDR check using precomputed objects if available, otherwise fallback
        if precomputed_db_nets:
            for w_net in precomputed_db_nets:
                try:
                    if is_cidr:
                        if input_obj.subnet_of(w_net): return True, "User Whitelist (CIDR)"
                    else:
                        if input_obj in w_net: return True, "User Whitelist (CIDR)"
                except: continue
        else:
            # Fallback (slow)
            for w_item in whitelist_db_items:
                if '/' in w_item:
                    try:
                        w_net = ipaddress.ip_network(w_item, strict=False)
                        if is_cidr:
                            if input_obj.subnet_of(w_net): return True, "User Whitelist (CIDR)"
                        else:
                            if input_obj in w_net: return True, "User Whitelist (CIDR)"
                    except ValueError: pass

    return False, None

def filter_whitelisted_items(items, whitelist_db_items):
    """
    Filters a list of items against safe list and user whitelist.
    Highly optimized for bulk processing.
    """
    if not items: return []
    
    # Precompute DB whitelist into sets and network objects
    db_items_set = set()
    db_nets = []
    if whitelist_db_items:
        for w in whitelist_db_items:
            w_str = w['item'] if isinstance(w, dict) else w
            if '/' in w_str:
                try: db_nets.append(ipaddress.ip_network(w_str, strict=False))
                except: db_items_set.add(w_str)
            else:
                db_items_set.add(w_str)

    filtered = []
    for item in items:
        # For tuples from parse_mixed_text (val, type)
        val = item[0] if isinstance(item, tuple) else item
        
        # Pass precomputed data to avoid repeated overhead
        whitelisted, _ = is_whitelisted(val, db_items_set, db_nets)
        if not whitelisted:
            filtered.append(item)
    return filtered

def aggregate_ips(ip_list):
    """
    Aggregates a list of IP addresses and CIDR strings into the smallest possible set of CIDR blocks.
    Uses Python's ipaddress.collapse_addresses.

    Args:
        ip_list (list): List of strings (e.g., ['192.168.1.1', '192.168.1.2', ...])

    Returns:
        list: A list of aggregated CIDR strings (e.g., ['192.168.1.0/24'])
    """
    if not ip_list:
        return []

    ipv4_networks = []
    ipv6_networks = []

    for item in ip_list:
        try:
            # strict=False allows bits set after the prefix len, helpful for dirty feeds
            net = ipaddress.ip_network(item, strict=False)
            if net.version == 4:
                ipv4_networks.append(net)
            else:
                ipv6_networks.append(net)
        except ValueError:
            # Not a valid IP/CIDR, skip it
            continue

    # The magic happens here: collapse_addresses merges adjacent and overlapping networks
    collapsed_v4 = ipaddress.collapse_addresses(ipv4_networks)
    collapsed_v6 = ipaddress.collapse_addresses(ipv6_networks)

    # Convert back to strings
    result = [str(net) for net in collapsed_v4] + [str(net) for net in collapsed_v6]
    return result

def validate_indicator(item):
    """
    Validates if an item is a valid IP address, CIDR, or URL.
    Returns: (bool, type_string)
    """
    if not item:
        return False, "Empty"

    # 1. Check IP/CIDR
    try:
        ipaddress.ip_network(item, strict=False)
        return True, "ip/cidr"
    except ValueError:
        pass

    # 2. Check URL / Domain
    # Very basic validation for domains/urls
    from urllib.parse import urlparse
    parsed = urlparse(item)
    
    # If it has a scheme (http/https), check if it has a netloc (domain)
    if parsed.scheme in ('http', 'https'):
        if parsed.netloc:
            return True, "url"
    
    # If no scheme, check if it looks like a domain (has a dot, no spaces)
    if '.' in item and ' ' not in item and not item.startswith('.'):
        # Basic check for common domain characters
        import re
        if re.match(r'^[a-zA-Z0-9\-\.]+$', item):
            return True, "domain"

    return False, "invalid"

def get_proxy_settings():
    """
    Retrieves proxy settings from config and formats them for requests/aiohttp.
    Returns:
        tuple: (proxies_dict_for_requests, proxy_url_for_aiohttp, auth_for_aiohttp)
    """
    from .config_manager import read_config
    config = read_config()
    proxy_config = config.get('proxy', {})
    
    if not proxy_config.get('enabled'):
        return None, None, None
        
    server = proxy_config.get('server')
    port = proxy_config.get('port')
    username = proxy_config.get('username')
    password = proxy_config.get('password')
    
    if not server or not port:
        return None, None, None
        
    # Format: http://user:pass@host:port or http://host:port
    auth_string = ""
    if username and password:
        auth_string = f"{username}:{password}@"
        
    proxy_url = f"http://{auth_string}{server}:{port}"
    
    # Requests format
    proxies = {
        "http": proxy_url,
        "https": proxy_url
    }
    
    # Aiohttp Auth (if separate auth object needed, though URL encoding usually works)
    # Usually returning just the URL is enough for aiohttp if auth is embedded
    return proxies, proxy_url, None
