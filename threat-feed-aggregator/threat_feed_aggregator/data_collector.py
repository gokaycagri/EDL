import requests
import aiohttp
import logging
from .utils import get_proxy_settings
from .config_manager import read_config

logger = logging.getLogger(__name__)

async def get_async_session():
    """
    Creates an aiohttp ClientSession with custom DNS resolver if configured.
    """
    config = read_config()
    dns_config = config.get('dns', {})
    primary = dns_config.get('primary')
    secondary = dns_config.get('secondary')
    
    nameservers = []
    if primary: nameservers.append(primary)
    if secondary: nameservers.append(secondary)
    
    connector = None
    if nameservers:
        # aiohttp uses a custom resolver if provided
        resolver = aiohttp.AsyncResolver(nameservers=nameservers)
        connector = aiohttp.TCPConnector(resolver=resolver)
        logger.debug(f"Using custom DNS nameservers: {nameservers}")
    
    return aiohttp.ClientSession(connector=connector)

def fetch_data_from_url(url):
    """
    Fetches data from a given URL synchronously.

    Args:
        url (str): The URL to fetch data from.

    Returns:
        str: The content of the response, or None if the request fails.
    """
    try:
        proxies, _, _ = get_proxy_settings()
        response = requests.get(url, timeout=30, proxies=proxies)
        response.raise_for_status()
        return response.text
    except requests.exceptions.RequestException as e:
        logger.error(f"Error fetching data from {url}: {e}")
        return None

async def fetch_data_from_url_async(url):
    """
    Fetches data from a given URL asynchronously using custom DNS and Proxy.
    """
    try:
        _, proxy_url, _ = get_proxy_settings()
        async with await get_async_session() as session:
            async with session.get(url, timeout=30, proxy=proxy_url) as response:
                response.raise_for_status()
                return await response.text()
    except Exception as e:
        logger.error(f"Async error fetching data from {url}: {e}")
        return None