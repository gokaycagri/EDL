import logging
import os

import requests

from .config_manager import DATA_DIR
from .utils import aggregate_ips, get_proxy_settings

logger = logging.getLogger(__name__)

GITHUB_META_URL = "https://api.github.com/meta"

def fetch_github_data():
    """
    Fetches the official GitHub IP ranges JSON.
    """
    try:
        proxies, _, _ = get_proxy_settings()
        response = requests.get(GITHUB_META_URL, timeout=20, proxies=proxies)
        response.raise_for_status()
        return response.json()
    except Exception as e:
        logger.error(f"Failed to fetch GitHub data: {e}")
        return None

def process_github_feeds():
    """
    Fetches data and generates separate EDL files for Git, Web, Actions, and Hooks.
    Returns a status message.
    """
    data = fetch_github_data()
    if not data:
        return False, "Failed to fetch data from GitHub."

    # GitHub API provides these keys directly containing lists of CIDRs
    categories = {
        "Git": "git",          # IP addresses for git operations
        "Web": "web",          # IP addresses for GitHub.com website
        "Actions": "actions",  # IP addresses for GitHub Actions runners
        "Hooks": "hooks",      # IP addresses for Service Hooks
        "Pages": "pages"       # IP addresses for GitHub Pages
    }

    generated_files = []

    for label, key in categories.items():
        ips = data.get(key, [])
        if ips:
            # Aggregate IPs using our utility
            optimized_ips = aggregate_ips(ips)

            filename = f"github_{label.lower()}_ips.txt"
            file_path = os.path.join(DATA_DIR, filename)

            with open(file_path, 'w') as f:
                f.write("\n".join(optimized_ips))
            generated_files.append(filename)

    logger.info(f"Generated GitHub feeds: {', '.join(generated_files)}")
    return True, f"Successfully processed GitHub feeds. Generated {len(generated_files)} files."
