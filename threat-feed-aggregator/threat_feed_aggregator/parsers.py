import json
import csv
from io import StringIO
import re
import ipaddress
import logging

logger = logging.getLogger(__name__)

# Pre-compile regex patterns for performance
URL_PATTERN = re.compile(r"https?://(?:[-\w.]|(?:%[\da-fA-F]{2}))+")
DOMAIN_PATTERN = re.compile(r"^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,6}$")

def identify_indicator_type(indicator):
    """
    Identifies the type of the given indicator (IP, CIDR, Domain, URL, or Unknown).
    """
    indicator = indicator.strip()
    if not indicator:
        return "unknown"

    # Check for IP address or CIDR
    try:
        if '/' in indicator:
            ipaddress.ip_network(indicator, strict=False)
            return "cidr"
        else:
            ipaddress.ip_address(indicator)
            return "ip"
    except ValueError:
        pass # Not an IP or CIDR

    # Check for URL
    if URL_PATTERN.match(indicator):
        return "url"

    # Check for Domain
    if DOMAIN_PATTERN.match(indicator):
         return "domain"

    return "unknown"

def parse_text(raw_data):
    """
    Parses plain text data, with one indicator per line.
    """
    return [line.strip() for line in raw_data.splitlines() if line.strip() and not line.strip().startswith('#')]

def parse_json(raw_data, key=None):
    """
    Parses JSON data. Expects a list of strings or a list of objects.
    If a key is provided, it will be used to extract the indicator from each object.
    """
    try:
        data = json.loads(raw_data)
        if isinstance(data, list):
            if key and isinstance(data[0], dict):
                return [item[key] for item in data if key in item]
            else:
                return [str(item) for item in data]
    except (json.JSONDecodeError, IndexError):
        return []
    return []

def parse_csv(raw_data, column=0):
    """
    Parses CSV data. Expects the indicator to be in a specific column.
    """
    try:
        reader = csv.reader(StringIO(raw_data))
        # Skip empty rows or rows that might be headers
        return [row[column].strip() for row in reader if row and len(row) > column and row[column].strip()]
    except (csv.Error, IndexError):
        return []

def parse_mixed_text(raw_data, source_name="Unknown", **kwargs):
    """
    Parses mixed text data, identifying indicator types for each line.
    Returns a list of tuples: (indicator_value, indicator_type).
    Includes logging for progress tracking.
    """
    parsed_items = []
    lines = raw_data.splitlines()
    total_lines = len(lines)
    logger.info(f"[{source_name}] Starting parse of {total_lines} lines...")
    
    for i, line in enumerate(lines):
        stripped_line = line.strip()
        if not stripped_line or stripped_line.startswith('#'):
            continue
        
        indicator_type = identify_indicator_type(stripped_line)
        
        # Normalization for De-duplication
        if indicator_type == 'domain':
            stripped_line = stripped_line.lower()
        elif indicator_type == 'cidr':
            try:
                # Normalize CIDR (e.g., 192.168.1.1/24 -> 192.168.1.0/24)
                stripped_line = str(ipaddress.ip_network(stripped_line, strict=False))
            except ValueError:
                pass
        elif indicator_type == 'ip':
            try:
                # Normalize IP (e.g., remove leading zeros)
                stripped_line = str(ipaddress.ip_address(stripped_line))
            except ValueError:
                pass

        parsed_items.append((stripped_line, indicator_type))
        
        # Log progress every 50,000 lines
        if (i + 1) % 50000 == 0:
            logger.info(f"[{source_name}] Parsed {i + 1}/{total_lines} lines...")

    logger.info(f"[{source_name}] Parsing completed. Total items: {len(parsed_items)}")
    return parsed_items

# --- Smart Parsers (Standardized Output) ---

def parse_json_with_type(raw_data, key=None, **kwargs):
    items = parse_json(raw_data, key)
    normalized_items = []
    for item in items:
        itype = identify_indicator_type(item)
        if itype == 'domain':
            item = item.lower()
        elif itype == 'cidr':
            try:
                item = str(ipaddress.ip_network(item, strict=False))
            except: pass
        elif itype == 'ip':
            try:
                item = str(ipaddress.ip_address(item))
            except: pass
        normalized_items.append((item, itype))
    return normalized_items

def parse_csv_with_type(raw_data, column=0, **kwargs):
    # Ensure column is an integer
    try:
        column = int(column)
    except (ValueError, TypeError):
        column = 0
    items = parse_csv(raw_data, column)
    normalized_items = []
    for item in items:
        itype = identify_indicator_type(item)
        if itype == 'domain':
            item = item.lower()
        elif itype == 'cidr':
            try:
                item = str(ipaddress.ip_network(item, strict=False))
            except: pass
        elif itype == 'ip':
            try:
                item = str(ipaddress.ip_address(item))
            except: pass
        normalized_items.append((item, itype))
    return normalized_items

def get_parser(format_type):
    """
    Factory to get the parsing function based on format.
    The returned function always accepts (raw_data, **kwargs) and returns [(indicator, type), ...].
    """
    parsers = {
        'text': parse_mixed_text, # Default text parser to mixed as it's safer
        'json': parse_json_with_type,
        'csv': parse_csv_with_type,
        'mixed': parse_mixed_text
    }
    return parsers.get(format_type, parse_mixed_text)
