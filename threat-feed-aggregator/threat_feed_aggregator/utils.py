import ipaddress
import logging
import os
from datetime import datetime

import pytz

logger = logging.getLogger(__name__)

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SAFE_LIST_FILE = os.path.join(BASE_DIR, "data", "safe_list.txt")

def format_timestamp(ts_str, fmt='%d/%m/%Y %H:%M'):
    """
    Formats an ISO timestamp string using the configured system timezone.
    """
    if not ts_str or ts_str == 'N/A':
        return 'N/A'

    try:
        from .config_manager import read_config
        config = read_config()
        tz_name = config.get('timezone', 'UTC')
        target_tz = pytz.timezone(tz_name)

        # Parse ISO string
        if isinstance(ts_str, str):
            dt = datetime.fromisoformat(ts_str)
        else:
            dt = ts_str # Already a datetime object

        # Convert to target TZ
        if dt.tzinfo is None:
            dt = pytz.utc.localize(dt)

        local_dt = dt.astimezone(target_tz)
        return local_dt.strftime(fmt)
    except Exception as e:
        logger.warning(f"Error formatting timestamp {ts_str}: {e}")
        return str(ts_str)

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
        with open(SAFE_LIST_FILE) as f:
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
        with open(SAFE_LIST_FILE) as f:
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

def _check_global_safelist(indicator):
    """Checks against the hardcoded global safe list (IPs/CIDRs)."""
    try:
        if '/' in indicator:
            input_obj = ipaddress.ip_network(indicator, strict=False)
            for net in SAFE_NETWORKS:
                if input_obj.subnet_of(net):
                    return True, "Global Safe List (CIDR)"
        else:
            input_obj = ipaddress.ip_address(indicator)
            for net in SAFE_NETWORKS:
                if input_obj in net:
                    return True, "Global Safe List (CIDR)"
    except ValueError:
        pass
    return False, None

def is_whitelisted(indicator, whitelist_db_items=None, precomputed_db_nets=None):
    """
    Checks if an indicator is in the user-defined whitelist OR the global safe list.
    Supports IPs, CIDRs, and exact string matches for Domains.
    """
    # 1. Global Safe List Check
    # Check text items (Exact match for domains/IPs in file)
    if indicator in SAFE_ITEMS:
        return True, "Global Safe List (Exact)"
    
    # Check networks
    is_safe, reason = _check_global_safelist(indicator)
    if is_safe:
        return True, reason

    # 2. User-defined Whitelist Check
    if whitelist_db_items:
        # Exact Match Check
        if indicator in whitelist_db_items:
            return True, "User Whitelist (Exact)"

        # CIDR Match Check
        try:
            if '/' in indicator:
                input_obj = ipaddress.ip_network(indicator, strict=False)
                is_cidr = True
            else:
                input_obj = ipaddress.ip_address(indicator)
                is_cidr = False

            if precomputed_db_nets:
                for w_net in precomputed_db_nets:
                    try:
                        if is_cidr:
                            if input_obj.subnet_of(w_net):
                                return True, "User Whitelist (CIDR)"
                        else:
                            if input_obj in w_net:
                                return True, "User Whitelist (CIDR)"
                    except Exception:
                        continue
            else:
                # Fallback (slower path if nets not precomputed)
                for w_item in whitelist_db_items:
                    if '/' in w_item:
                        try:
                            w_net = ipaddress.ip_network(w_item, strict=False)
                            if is_cidr:
                                if input_obj.subnet_of(w_net):
                                    return True, "User Whitelist (CIDR)"
                            else:
                                if input_obj in w_net:
                                    return True, "User Whitelist (CIDR)"
                        except ValueError:
                            pass
        except ValueError:
            pass

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
                except Exception: db_items_set.add(w_str)
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
        if parsed.netloc and ' ' not in parsed.netloc:
            return True, "url"

    # If no scheme, check if it looks like a domain (has a dot, no spaces)
    if '.' in item and ' ' not in item and not item.startswith('.'):
        # Basic check for common domain characters
        import re
        if re.match(r'^[a-zA-Z0-9\-\.]+$', item):
            return True, "domain"
        
        # Check for scheme-less URLs (e.g. example.com/path)
        try:
            parsed_simulated = urlparse(f"http://{item}")
            if parsed_simulated.netloc and '.' in parsed_simulated.netloc:
                # Check if the host part is valid-ish
                if re.match(r'^[a-zA-Z0-9\-\.]+$', parsed_simulated.netloc):
                    return True, "url"
        except Exception:
            pass

    return False, "invalid"

def get_proxy_settings():
    """
    Retrieves proxy settings from config and formats them for requests/aiohttp.
    Ensures internal/local domains bypass the proxy.
    Returns:
        tuple: (proxies_dict_for_requests, proxy_url_for_aiohttp, None)
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

    # Use raw credentials for the proxy URL as dots/numbers don't need encoding
    # and some corporate proxies are sensitive to encoding.
    auth_string = ""
    if username and password:
        auth_string = f"{username}:{password}@"

    proxy_url = f"http://{auth_string}{server}:{port}"

    # Proxies dict for 'requests'
    # Adding explicit internal IPs and domains to bypass proxy
    proxies = {
        "http": proxy_url,
        "https": proxy_url,
        "no_proxy": "localhost,127.0.0.1,10.236.79.11,10.235.30.21,10.235.31.11,ddd.mfa.gov.tr,fortiproxy.mfa.gov.tr,fortiproxy01.mfa.gov.tr,.mfa.gov.tr,10.0.0.0/8,172.16.0.0/12,192.168.0.0/16"
    }

    return proxies, proxy_url, None
