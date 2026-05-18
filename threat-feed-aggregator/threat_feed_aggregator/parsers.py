import csv
from io import StringIO
import ipaddress
import json
import logging
import re

logger = logging.getLogger(__name__)

# Pre-compile regex patterns for performance
URL_PATTERN = re.compile(r"https?://(?:[-\w.]|(?:%[\da-fA-F]{2}))+")
# Updated DOMAIN_PATTERN to support modern TLDs (up to 63 chars)
DOMAIN_PATTERN = re.compile(r"^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,63}$")
# Simple check for IP candidates (digits and dots or colons)
IP_CANDIDATE_PATTERN = re.compile(r"^[0-9a-fA-F:./]+$")


def identify_indicator_type(indicator):
    """
    Identifies the type of the given indicator (IP, CIDR, Domain, URL, or Unknown).
    Optimized with pre-checks.
    """
    indicator = indicator.strip()
    if not indicator:
        return "unknown"

    # Optimization: Only try parsing as IP if it looks like one
    if IP_CANDIDATE_PATTERN.match(indicator):
        try:
            if "/" in indicator:
                ipaddress.ip_network(indicator, strict=False)
                return "cidr"
            else:
                ipaddress.ip_address(indicator)
                return "ip"
        except ValueError:
            pass  # Not a valid IP/CIDR despite matching basic char pattern

    # Check for URL
    if URL_PATTERN.match(indicator):
        return "url"

    # Check for Schemeless URL (e.g. domain.com/path)
    if "/" in indicator and not indicator.startswith("/"):
        parts = indicator.split("/", 1)
        # Check if the domain part is valid
        if DOMAIN_PATTERN.match(parts[0]):
            return "url"

    # Check for Domain
    if DOMAIN_PATTERN.match(indicator):
        return "domain"

    return "unknown"


def parse_text(raw_data):
    """
    Parses plain text data, with one indicator per line.
    """
    return [line.strip() for line in raw_data.splitlines() if line.strip() and not line.strip().startswith("#")]


def parse_json(raw_data, key=None):
    """
    Parses JSON data. Expects a list of strings or a list of objects.
    If a key is provided, it will be used to extract the indicator from each object.
    Supports dot notation for nested keys (e.g. 'attributes.ip_address').
    """
    try:
        data = json.loads(raw_data)
        if isinstance(data, list):
            if key:
                # Handle nested keys
                keys = key.split(".")
                results = []
                for item in data:
                    if not isinstance(item, dict):
                        continue
                    val = item
                    try:
                        for k in keys:
                            if isinstance(val, dict):
                                val = val.get(k)
                            else:
                                val = None
                                break
                        if val:
                            results.append(str(val))
                    except AttributeError:
                        continue
                return results
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


def normalize_indicator(indicator, itype=None):
    """
    Standardizes indicators for de-duplication.
    """
    if not itype:
        itype = identify_indicator_type(indicator)

    if itype == "domain":
        return indicator.lower(), itype
    elif itype == "cidr":
        try:
            return str(ipaddress.ip_network(indicator, strict=False)), itype
        except (ValueError, TypeError):
            pass
    elif itype == "ip":
        try:
            return str(ipaddress.ip_address(indicator)), itype
        except (ValueError, TypeError):
            pass

    return indicator, itype


def parse_mixed_text(raw_data, source_name="Unknown", **kwargs):
    """
    Highly optimized mixed text parser with centralized normalization.
    """
    parsed_items = []
    lines = raw_data.splitlines()
    total_lines = len(lines)
    logger.info(f"[{source_name}] Starting parse of {total_lines} lines...")

    for i, line in enumerate(lines):
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue

        normalized, itype = normalize_indicator(stripped)
        parsed_items.append((normalized, itype))

        if (i + 1) % 50000 == 0:
            logger.info(f"[{source_name}] Parsed {i + 1}/{total_lines} lines...")

    return parsed_items


def parse_json_with_type(raw_data, key=None, **kwargs):
    items = parse_json(raw_data, key)
    return [normalize_indicator(item) for item in items]


def parse_csv_with_type(raw_data, column=0, **kwargs):
    try:
        column = int(column)
    except (ValueError, TypeError):
        column = 0
    items = parse_csv(raw_data, column)
    return [normalize_indicator(item) for item in items]


_SGB_TYPE_MAP = {"domain": "domain", "ip": "ip", "url": "url", "cidr": "cidr"}


def parse_sgb(raw_data, source_name="Unknown", **kwargs):
    """
    Parses SGB (Siber Güvenlik Başkanlığı) feed data.
    Expects tab-separated 'indicator<TAB>type' lines as returned by _fetch_sgb_paginated.
    The type field is provided by SGB API directly (domain/ip/url), which avoids regex re-detection.
    Falls back to identify_indicator_type() if type is missing or unrecognized.
    """
    items = []
    lines = raw_data.splitlines()
    logger.info(f"[{source_name}] Starting SGB parse of {len(lines)} items...")

    for line in lines:
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        if "\t" in line:
            raw_indicator, sgb_type = line.split("\t", 1)
            raw_indicator = raw_indicator.strip()
            itype = _SGB_TYPE_MAP.get(sgb_type.strip().lower())
            if itype:
                normalized, _ = normalize_indicator(raw_indicator, itype)
            else:
                normalized, itype = normalize_indicator(raw_indicator)
        else:
            normalized, itype = normalize_indicator(line)
        if normalized and itype != "unknown":
            items.append((normalized, itype))

    return items


def get_parser(format_type):
    """
    Factory to get the parsing function based on format.
    The returned function always accepts (raw_data, **kwargs) and returns [(indicator, type), ...].
    """
    parsers = {
        "text": parse_mixed_text,  # Default text parser to mixed as it's safer
        "json": parse_json_with_type,
        "csv": parse_csv_with_type,
        "mixed": parse_mixed_text,
        "sgb": parse_sgb,  # Siber Güvenlik Başkanlığı — tab-separated url\ttype format
    }
    return parsers.get(format_type, parse_mixed_text)
