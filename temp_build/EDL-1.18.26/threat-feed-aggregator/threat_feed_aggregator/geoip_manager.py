import logging
import os
from functools import lru_cache

import geoip2.database

logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO) # Set to INFO for production

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DATA_DIR = os.path.join(BASE_DIR, "data")
GEOIP_DB_PATH = os.path.join(DATA_DIR, "GeoLite2-Country.mmdb")

# Global reader instance to avoid repeated file opens
_geoip_reader = None

def get_reader():
    global _geoip_reader
    if _geoip_reader is None:
        if os.path.exists(GEOIP_DB_PATH):
            try:
                _geoip_reader = geoip2.database.Reader(GEOIP_DB_PATH)
            except Exception as e:
                logger.error(f"Error opening GeoIP DB: {e}")
    return _geoip_reader

@lru_cache(maxsize=10000)
def get_country_code(ip_address):
    """
    Returns the ISO country code for an IP address.
    Optimized with singleton reader and LRU cache.
    """
    reader = get_reader()
    if not reader:
        return None

    try:
        response = reader.country(ip_address)
        return response.country.iso_code
    except geoip2.errors.AddressNotFoundError:
        return None
    except Exception as e:
        logger.error(f"GeoIP lookup failed for {ip_address}: {e}")
        return None
