import json
import csv
from io import StringIO
from .utils import aggregate_ips


def format_generic(indicator_dict, include_types=None, output_format='text', delimiter='\n'):
    """
    Generates a generic output for indicators.
    
    Args:
        indicator_dict (dict): Dictionary of indicators.
        include_types (list): List of types to include (e.g. ['ip', 'domain']). If None, includes all.
        output_format (str): 'text', 'csv', or 'json'.
        delimiter (str): Delimiter for 'text' format (default newline).
        
    Returns:
        str: Formatted output string.
    """
    # Optimized for Text format to save memory
    if output_format == 'text':
        filtered_indicators = (
            ind for ind, det in indicator_dict.items()
            if not include_types or det.get('type') in include_types
        )
        return delimiter.join(filtered_indicators)

    items = []
    for indicator, details in indicator_dict.items():
        if include_types and details.get('type') not in include_types:
            continue
        items.append({
            'indicator': indicator,
            'type': details.get('type'),
            'risk_score': details.get('risk_score'),
            'country': details.get('country')
        })

    if output_format == 'json':
        return json.dumps(items, indent=2)
    
    elif output_format == 'csv':
        output = StringIO()
        writer = csv.writer(output)
        writer.writerow(['indicator', 'type', 'risk_score', 'country'])
        for item in items:
            writer.writerow([item['indicator'], item['type'], item['risk_score'], item['country']])
        return output.getvalue()
        
    else: # text
        # Just return the indicators
        return delimiter.join([item['indicator'] for item in items])


def format_for_palo_alto(indicator_dict):
    """
    Formats a dictionary of indicators (from get_all_indicators) for Palo Alto EDL.
    Includes only 'ip' and 'cidr' types, aggregated into CIDR blocks.

    Args:
        indicator_dict (dict): A dictionary of indicators with their details.

    Returns:
        str: A string with one IP/CIDR per line.
    """
    raw_items = []
    for indicator, details in indicator_dict.items():
        if details.get('type') in ['ip', 'cidr']:
            raw_items.append(indicator)

    # Optimize using CIDR aggregation
    aggregated_items = aggregate_ips(raw_items)

    return "\n".join(aggregated_items)

def format_for_palo_alto_domain(indicator_dict):
    """
    Formats dictionary for Palo Alto Domain List EDL.
    Includes 'domain' and 'url' types.
    """
    items = []
    for indicator, details in indicator_dict.items():
        if details.get('type') in ['domain', 'url']:
            items.append(indicator)
    return "\n".join(items)

def format_for_fortinet_domain(indicator_dict):
    """
    Formats dictionary for Fortinet Domain List EDL.
    Includes 'domain' and 'url' types.
    """
    items = []
    for indicator, details in indicator_dict.items():
        if details.get('type') in ['domain', 'url']:
            items.append(indicator)
    return "\n".join(items)

def format_for_fortinet(indicator_dict):
    """
    Formats a dictionary of indicators (from get_all_indicators) for Fortinet Fabric Connector.
    Includes only 'ip' and 'cidr' types, aggregated into CIDR blocks.

    Args:
        indicator_dict (dict): A dictionary of indicators with their details.

    Returns:
        str: A string with one IP/CIDR per line, suitable for Fortinet.
    """
    raw_items = []
    for indicator, details in indicator_dict.items():
        if details.get('type') in ['ip', 'cidr']:
            raw_items.append(indicator)

    # Optimize using CIDR aggregation
    aggregated_items = aggregate_ips(raw_items)

    return "\n".join(aggregated_items)

def format_for_url_list(indicator_dict):
    """
    Formats a dictionary of indicators for a URL/Domain list.
    Includes only 'url' and 'domain' types.

    Args:
        indicator_dict (dict): A dictionary of indicators with their details.

    Returns:
        str: A string with one URL/Domain per line.
    """
    items = []
    for indicator, details in indicator_dict.items():
        if details.get('type') in ['url', 'domain']:
            items.append(indicator)
    return "\n".join(items)

