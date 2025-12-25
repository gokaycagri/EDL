import requests
import aiohttp
import logging
from .utils import get_proxy_settings

logger = logging.getLogger(__name__)

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
    Fetches data from a given URL asynchronously.

    Args:
        url (str): The URL to fetch data from.

    Returns:
        str: The content of the response, or None if the request fails.
    """
    try:
        _, proxy_url, _ = get_proxy_settings()
        async with aiohttp.ClientSession() as session:
            async with session.get(url, timeout=30, proxy=proxy_url) as response:
                response.raise_for_status()
                return await response.text()
    except Exception as e:
        logger.error(f"Async error fetching data from {url}: {e}")
        return None