import logging

import aiohttp
import requests

from .utils import get_proxy_settings

logger = logging.getLogger(__name__)

async def get_async_session(verify_ssl=True):
    """
    Creates an aiohttp ClientSession with a robust threaded DNS resolver.
    """
    resolver = aiohttp.ThreadedResolver()
    # We set verify_ssl at the connector level
    connector = aiohttp.TCPConnector(resolver=resolver, verify_ssl=verify_ssl)

    return aiohttp.ClientSession(connector=connector)

def fetch_data_from_url(url, auth=None):
    """
    Fetches data from a given URL synchronously.
    """
    try:
        proxies, _, proxy_auth = get_proxy_settings()
        
        # SSL Verification logic: Disable for internal MFA domains
        verify_ssl = True
        if "mfa.gov.tr" in url or "10.236.79.11" in url:
            verify_ssl = False
            import urllib3
            urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

        response = requests.get(url, timeout=30, proxies=proxies, auth=auth, proxy_auth=proxy_auth, verify=verify_ssl)
        if response.status_code == 404:
            logger.warning(f"FEED NOT FOUND (404): The source at {url} is no longer available.")
            return None
        response.raise_for_status()
        return response.text
    except requests.exceptions.RequestException as e:
        if hasattr(e.response, 'status_code') and e.response.status_code == 404:
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
        
        # SSL Verification logic
        is_internal = "mfa.gov.tr" in url or "10.236.79.11" in url
        
        # Internal helper to perform the actual GET
        async def do_get(s):
            # For aiohttp, we pass ssl=False to skip verification for internal sites
            ssl_param = False if is_internal else None
            async with s.get(url, timeout=30, proxy=proxy_url, auth=auth, ssl=ssl_param) as response:
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
