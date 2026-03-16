import logging

import aiohttp
import requests

from .config_manager import read_config
from .utils import get_proxy_settings

logger = logging.getLogger(__name__)

async def get_async_session(verify_ssl=True):
    """
    Creates an aiohttp ClientSession with a robust threaded DNS resolver.
    """
    resolver = aiohttp.ThreadedResolver()
    # We set verify_ssl at the connector level
    ssl_context = None if verify_ssl else False
    connector = aiohttp.TCPConnector(resolver=resolver, ssl=ssl_context)

    return aiohttp.ClientSession(connector=connector)

def _is_ssl_bypass_url(url):
    """Check if URL is in the configured SSL bypass list."""
    config = read_config()
    bypass_hosts = config.get('ssl_bypass_hosts', [])
    return any(host in url for host in bypass_hosts)

def fetch_data_from_url(url, auth=None):
    """
    Fetches data from a given URL synchronously.
    """
    try:
        proxies, _, proxy_auth = get_proxy_settings()

        # SSL verification — bypass only for configured internal hosts
        verify_ssl = not _is_ssl_bypass_url(url)
        if not verify_ssl:
            import urllib3
            urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

        response = requests.get(url, timeout=30, proxies=proxies, auth=auth, proxy_auth=proxy_auth, verify=verify_ssl)
        if response.status_code == 404:
            logger.warning(f"FEED NOT FOUND (404): The source at {url} is no longer available.")
            return None
        response.raise_for_status()
        return response.text
    except requests.exceptions.RequestException as e:
        if getattr(e, 'response', None) is not None and e.response.status_code == 404:
             logger.warning(f"FEED NOT FOUND (404): The source at {url} is no longer available.")
        else:
             logger.error(f"Error fetching data from {url}: {e}")
        return None

async def fetch_data_from_url_async(url, session=None, auth=None):
    """
    Highly Optimized: Fetches data asynchronously.
    """
    try:
        _, proxy_url, _ = get_proxy_settings()

        # SSL verification — bypass only for configured hosts
        is_internal = _is_ssl_bypass_url(url)
        _timeout = aiohttp.ClientTimeout(total=30)

        # Internal helper to perform the actual GET
        async def do_get(s):
            ssl_param = False if is_internal else None
            async with s.get(url, timeout=_timeout, proxy=proxy_url, auth=auth, ssl=ssl_param) as response:
                if response.status == 404:
                    return None
                response.raise_for_status()
                return await response.text()

        if session:
            return await do_get(session)
        else:
            # For internal sites, we create a session that doesn't verify SSL
            async with await get_async_session(verify_ssl=not is_internal) as new_session:
                return await do_get(new_session)

    except Exception as e:
        logger.error(f"Async fetch failed for {url}: {e}")
        return None
