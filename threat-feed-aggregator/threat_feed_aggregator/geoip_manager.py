import os
import logging
import geoip2.database

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DATA_DIR = os.path.join(BASE_DIR, "data")
GEOIP_DB_PATH = os.path.join(DATA_DIR, "GeoLite2-Country.mmdb")

def get_country_code(ip_address):
    """
    Returns the ISO country code for an IP address.
    Returns 'Unknown' if DB not found or IP not found.
    """
    if not os.path.exists(GEOIP_DB_PATH):
        return None

    try:
        with geoip2.database.Reader(GEOIP_DB_PATH) as reader:
            response = reader.country(ip_address)
            return response.country.iso_code
    except Exception as e:
        # logging.debug(f"GeoIP lookup failed for {ip_address}: {e}")
        return None
