import logging
import os
import re

import requests

from .config_manager import DATA_DIR
from .utils import aggregate_ips, get_proxy_settings

logger = logging.getLogger(__name__)

# Microsoft Download Page for Azure IP Ranges and Service Tags – Public Cloud
DOWNLOAD_PAGE_URL = "https://www.microsoft.com/en-us/download/confirmation.aspx?id=56519"

def get_latest_azure_json_url():
    """
    Scrapes the Microsoft download page to find the dynamic link for the latest ServiceTags JSON.
    """
    try:
        headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
        }
        proxies, _, _ = get_proxy_settings()
        response = requests.get(DOWNLOAD_PAGE_URL, headers=headers, timeout=10, proxies=proxies)
        response.raise_for_status()

        # Regex to find the JSON download link
        # Look for href containing "ServiceTags_Public" and ending in .json
        match = re.search(r'href="([^"]*ServiceTags_Public[^"]+\.json)"', response.text)
        if match:
            return match.group(1)
        else:
            # Fallback regex attempt (sometimes plain link)
            match = re.search(r'(https://download.microsoft.com/download/.*?\.json)', response.text)
            if match:
                 return match.group(1)

            logger.error("Could not find Azure JSON download link on the page.")
            return None
    except Exception as e:
        logger.error(f"Error scraping Azure download page: {e}")
        return None

def process_azure_feeds():
    """
    Downloads the latest Azure Service Tags JSON and generates EDL files for key services.
    """
    json_url = get_latest_azure_json_url()
    if not json_url:
        return False, "Could not determine download URL for Azure IPs."

    try:
        logger.info(f"Downloading Azure data from: {json_url}")
        proxies, _, _ = get_proxy_settings()
        # Disable verify due to potential corporate proxy/MITM or missing CA bundle in container
        response = requests.get(json_url, timeout=30, proxies=proxies, verify=False)
        response.raise_for_status()
        data = response.json()
    except Exception as e:
        return False, f"Failed to download Azure JSON: {e}"

    # Services/Regions we want to extract
    # Mapping: Output Filename -> Filter Function
    targets = {
        "azure_all_ips.txt": lambda v: True, # All Azure IPs
        "azure_sql_ips.txt": lambda v: v['name'].startswith('Sql'),
        "azure_storage_ips.txt": lambda v: v['name'].startswith('Storage'),
        "azure_westeurope_ips.txt": lambda v: v['properties']['region'] == 'westeurope',
        "azure_northeurope_ips.txt": lambda v: v['properties']['region'] == 'northeurope'
    }

    generated_files = []

    # Iterate over all values in the JSON
    values = data.get('values', [])

    # Pre-calculate lists for targets
    results = {k: [] for k in targets.keys()}

    for item in values:
        address_prefixes = item.get('properties', {}).get('addressPrefixes', [])
        if not address_prefixes:
            continue

        for filename, filter_func in targets.items():
            if filter_func(item):
                results[filename].extend(address_prefixes)

    # Save Files
    for filename, ips in results.items():
        if ips:
            optimized_ips = aggregate_ips(ips)
            file_path = os.path.join(DATA_DIR, filename)
            with open(file_path, 'w') as f:
                f.write("\n".join(optimized_ips))
            generated_files.append(filename)

    logger.info(f"Generated Azure feeds: {', '.join(generated_files)}")
    return True, f"Successfully processed Azure feeds. Generated {len(generated_files)} files."
