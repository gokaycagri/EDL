import json
import csv
from io import StringIO
import re
import ipaddress

# Pre-compile regex patterns for performance
URL_PATTERN = re.compile(r"https?://(?:[-\w.]|(?:%[\da-fA-F]{2}))+")
DOMAIN_PATTERN = re.compile(r"^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,6}$")

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

def identify_indicator_type(indicator):
    """
    Identifies the type of the given indicator (IP, CIDR, Domain, URL, or Unknown).
    """
    indicator = indicator.strip()
    if not indicator:
        return "unknown"

    # Check for IP address or CIDR
    # ipaddress module is generally efficient enough, but regex could be used for pre-filtering if needed.
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

def parse_mixed_text(raw_data):
    """
    Parses mixed text data, identifying indicator types for each line.
    Returns a list of tuples: (indicator_value, indicator_type).
    """
    parsed_items = []
    lines = raw_data.splitlines()
    for line in lines:
        stripped_line = line.strip()
        if not stripped_line or stripped_line.startswith('#'):
            continue
        
        indicator_type = identify_indicator_type(stripped_line)
        parsed_items.append((stripped_line, indicator_type))
    return parsed_items
