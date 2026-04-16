import concurrent.futures
import logging

import requests
import whois

from ..constants import REQUEST_TIMEOUT_DEFAULT, USER_AGENT
from ..utils import get_proxy_settings

logger = logging.getLogger(__name__)

_WHOIS_TIMEOUT = 10  # seconds


class InvestigationService:
    @staticmethod
    def lookup_ip(ip_address):
        """
        Performs WHOIS, IP-API, and THC lookup for an IP address.
        Returns: dict with keys 'success', 'geo', 'whois_data', 'data'
        """
        # 1. WHOIS (with timeout to prevent thread blocking)
        whois_data_str = "WHOIS lookup failed or no data available."
        try:
            with concurrent.futures.ThreadPoolExecutor(max_workers=1) as executor:
                future = executor.submit(whois.whois, ip_address)
                whois_info = future.result(timeout=_WHOIS_TIMEOUT)
            whois_data_str = whois_info.text if whois_info and whois_info.text else "No WHOIS data found."
        except concurrent.futures.TimeoutError:
            logger.warning(f"WHOIS lookup timed out for {ip_address}")
            whois_data_str = "WHOIS lookup timed out."
        except Exception as whois_e:
            logger.warning(f"WHOIS lookup failed for {ip_address}: {whois_e}")
            whois_data_str = f"WHOIS lookup error: {whois_e}"

        proxies, _, _ = get_proxy_settings()

        # 2. IP-API.com (HTTPS for confidentiality)
        ip_api_data = {}
        try:
            ip_api_url = f"https://ip-api.com/json/{ip_address}?fields=status,message,continent,country,countryCode,region,regionName,city,zip,lat,lon,timezone,isp,org,as,mobile,proxy,hosting,query"
            r_ip = requests.get(ip_api_url, timeout=REQUEST_TIMEOUT_DEFAULT, proxies=proxies)
            if r_ip.status_code == 200:
                ip_api_data = r_ip.json()
        except Exception as e:
            logger.warning(f"IP-API lookup failed: {e}")

        # 3. THC API (Reverse DNS)
        thc_data = {}
        try:
            target_url = "https://ip.thc.org/api/v1/lookup"
            payload = {"ip_address": ip_address, "limit": 100}
            headers = {"Content-Type": "application/json", "User-Agent": USER_AGENT}
            response = requests.post(
                target_url, json=payload, headers=headers, timeout=REQUEST_TIMEOUT_DEFAULT, proxies=proxies
            )
            if response.status_code == 200:
                thc_data = response.json()
        except Exception as e:
            logger.warning(f"THC lookup failed: {e}")

        return {"success": True, "geo": ip_api_data, "data": thc_data, "whois_data": whois_data_str}
