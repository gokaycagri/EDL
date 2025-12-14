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

def is_whitelisted(indicator, whitelist_db_items=None):
    """
    Checks if an indicator is in the user-defined whitelist OR the global safe list.
    Supports IPs, CIDRs, and exact string matches for Domains.
    """
    # 1. Check Global Safe List (Exact Match)
    if indicator in SAFE_ITEMS:
        return True, "Global Safe List"

    # 2. Check Global Safe List (CIDR)
    try:
        if '/' in indicator:
            input_net = ipaddress.ip_network(indicator, strict=False)
            for net in SAFE_NETWORKS:
                if input_net.subnet_of(net): 
                    return True, "Global Safe List (CIDR)"
        else:
            input_ip = ipaddress.ip_address(indicator)
            for net in SAFE_NETWORKS:
                if input_ip in net:
                    return True, "Global Safe List (CIDR)"
    except ValueError:
        pass 

    # 3. Check User DB Whitelist
    if whitelist_db_items:
        if indicator in whitelist_db_items:
            return True, "User Whitelist"
        
        try:
            input_obj = None
            is_input_cidr = '/' in indicator
            
            if is_input_cidr:
                input_obj = ipaddress.ip_network(indicator, strict=False)
            else:
                input_obj = ipaddress.ip_address(indicator)

            for w_item in whitelist_db_items:
                if '/' in w_item:
                    try:
                        w_net = ipaddress.ip_network(w_item, strict=False)
                        if is_input_cidr:
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
    Returns filtered list.
    """
    filtered = []
    for item in items:
        whitelisted, reason = is_whitelisted(item, whitelist_db_items)
        if not whitelisted:
            filtered.append(item)
    return filtered
