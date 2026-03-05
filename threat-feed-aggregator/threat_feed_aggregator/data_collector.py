import logging

import aiohttp
import requests

from .utils import get_proxy_settings

logger = logging.getLogger(__name__)

async def get_async_session():
    """
    Creates an aiohttp ClientSession with a robust threaded DNS resolver.
    Custom DNS nameservers should be configured at the OS/Docker level.
    """
    # Use ThreadedResolver for maximum compatibility and stability
    resolver = aiohttp.ThreadedResolver()
    connector = aiohttp.TCPConnector(resolver=resolver)

    return aiohttp.ClientSession(connector=connector)

def fetch_data_from_url(url, auth=None):
    """
    Fetches data from a given URL synchronously.

    Args:
        url (str): The URL to fetch data from.
        auth (tuple): Optional (username, password) tuple for Basic Auth (Target Site).

    Returns:
        str: The content of the response, or None if the request fails.
    """
    try:
        proxies, _, proxy_auth = get_proxy_settings()
        # Use proxies dict and explicit proxy auth for reliability
        response = requests.get(url, timeout=30, proxies=proxies, auth=auth, proxy_auth=proxy_auth)
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
    Reuses provided session or creates a temporary one with optimized settings.
    """
    try:
        _, proxy_url, _ = get_proxy_settings()
        
        # Note: For aiohttp, auth is the target site auth, 
        # proxy_auth is the proxy credentials.
        # However, our get_proxy_settings returns a pre-encoded proxy_url for aiohttp.
        # If proxy_url is None, it won't use a proxy.
        
        # Internal helper to perform the actual GET
        async def do_get(s):
            async with s.get(url, timeout=30, proxy=proxy_url, auth=auth) as response:
                if response.status == 404:
                    return None
                response.raise_for_status()
                return await response.text()

        if session:
            return await do_get(session)
        else:
            async with await get_async_session() as new_session:
                return await do_get(new_session)

    except Exception as e:
        logger.error(f"Async fetch failed for {url}: {e}")
        return None
