import logging
import os
import uuid

import requests

from .config_manager import DATA_DIR
from .utils import aggregate_ips, get_proxy_settings

logger = logging.getLogger(__name__)

MS_ENDPOINT_URL = "https://endpoints.office.com/endpoints/worldwide?clientrequestid={}"

def fetch_microsoft_data():
    """
    Fetches the official Microsoft 365 IP and URL data.
    """
    request_id = str(uuid.uuid4())
    url = MS_ENDPOINT_URL.format(request_id)

    try:
        proxies, _, _ = get_proxy_settings()
        response = requests.get(url, timeout=20, proxies=proxies)
        response.raise_for_status()
        return response.json()
    except Exception as e:
        logger.error(f"Failed to fetch Microsoft data: {e}")
        return None

def process_microsoft_feeds():
    """
    Fetches data and generates separate EDL files for Exchange, SharePoint, and Teams.
    Returns a status message.
    """
    data = fetch_microsoft_data()
    if not data:
        return False, "Failed to fetch data from Microsoft."

    # Categories to extract
    categories = {
        "Exchange": {"ips": [], "urls": []},
        "Skype": {"ips": [], "urls": []}, # Skype includes Teams
        "SharePoint": {"ips": [], "urls": []},
        "Common": {"ips": [], "urls": []}
    }

    count = 0
    for item in data:
        service_area = item.get('serviceArea')
        if service_area in categories:
            # IPs (v4 and v6)
            if 'ips' in item:
                categories[service_area]["ips"].extend(item['ips'])
            # URLs
            if 'urls' in item:
                categories[service_area]["urls"].extend(item['urls'])
            count += 1

    generated_files = []

    # Process and Save Files
    for service, content in categories.items():
        # 1. IPs - Aggregated/Optimized
        if content["ips"]:
            # Microsoft IPs are usually already CIDRs, but aggregation ensures optimization
            optimized_ips = aggregate_ips(content["ips"])
            filename = f"ms365_{service.lower()}_ips.txt"
            file_path = os.path.join(DATA_DIR, filename)

            with open(file_path, 'w') as f:
                f.write("\n".join(optimized_ips))
            generated_files.append(filename)

        # 2. URLs - Raw List
        if content["urls"]:
            # Sort and deduplicate
            unique_urls = sorted(list(set(content["urls"])))
            filename = f"ms365_{service.lower()}_urls.txt"
            file_path = os.path.join(DATA_DIR, filename)

            with open(file_path, 'w') as f:
                f.write("\n".join(unique_urls))
            generated_files.append(filename)

    logger.info(f"Generated Microsoft 365 feeds: {', '.join(generated_files)}")
    return True, f"Successfully processed {count} rule sets. Generated {len(generated_files)} files."
