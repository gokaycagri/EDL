import requests
import logging
import re
import json
from requests.auth import HTTPBasicAuth
from .utils import get_proxy_settings

logger = logging.getLogger(__name__)

class SimpleTAXIIClient:
    def __init__(self, url, username=None, password=None, verify_ssl=True):
        self.url = url.rstrip('/')
        self.username = username
        self.password = password
        self.verify_ssl = verify_ssl
        self.session = requests.Session()
        
        # Configure Proxy
        proxies, _, _ = get_proxy_settings()
        if proxies:
            self.session.proxies.update(proxies)
        
        if self.username and self.password:
            self.session.auth = HTTPBasicAuth(self.username, self.password)
            
        # TAXII Headers
        self.headers = {
            'Accept': 'application/taxii+json;version=2.1',
            # Some servers might require v2.0
        }

    def _make_request(self, endpoint, params=None):
        full_url = f"{self.url}{endpoint}"
        try:
            # Try v2.1 first
            response = self.session.get(full_url, headers=self.headers, verify=self.verify_ssl, params=params)
            
            # Fallback for content-type negotiation if needed, but for now keep it simple
            response.raise_for_status()
            return response.json()
        except Exception as e:
            logger.error(f"TAXII Request Error to {full_url}: {e}")
            return None

    def get_collection_objects(self, collection_id):
        """
        Fetches objects from a specific collection.
        This assumes the user provided a direct URL to the API Root or we construct it.
        Standard path: /collections/{id}/objects/
        """
        # If the user provided URL is the Collection URL itself, handle that
        # Otherwise assume it's the API Root
        
        endpoint = f"/collections/{collection_id}/objects/"
        data = self._make_request(endpoint, params={"match[type]": "indicator"})
        
        if not data or 'objects' not in data:
            logger.warning(f"No objects found in collection {collection_id}")
            return []
            
        return data['objects']

def extract_indicators_from_stix(stix_objects):
    """
    Parses STIX 2.x Indicator objects and extracts IPs, Domains, URLs using Regex.
    Returns a list of tuples: (indicator_value, indicator_type)
    """
    extracted = []
    
    # Regex patterns for STIX patterning language
    # Example: [ipv4-addr:value = '198.51.100.1']
    patterns = {
        'ip': re.compile(r"ipv4-addr:value\s*=\s*['"]([\d.]+)['"]"),
        'cidr': re.compile(r"ipv4-addr:value\s*=\s*['"]([\d./]+)['"]"), # Sometimes CIDR is same field
        'domain': re.compile(r"domain-name:value\s*=\s*['"]([^'"]+)['"]"),
        'url': re.compile(r"url:value\s*=\s*['"]([^'"]+)['"]")
    }
    
    for obj in stix_objects:
        if obj.get('type') != 'indicator' or 'pattern' not in obj:
            continue
            
        pattern_str = obj['pattern']
        
        # Try to match patterns
        # Note: STIX patterns can be complex (AND/OR). This simple extractor 
        # focuses on atomic indicators.
        
        # IP / CIDR
        for match in patterns['ip'].findall(pattern_str):
            if '/' in match:
                extracted.append((match, 'cidr'))
            else:
                extracted.append((match, 'ip'))
                
        # Domain
        for match in patterns['domain'].findall(pattern_str):
            extracted.append((match, 'domain'))
            
        # URL
        for match in patterns['url'].findall(pattern_str):
            extracted.append((match, 'url'))
            
    return extracted

def fetch_and_parse_taxii(url, collection_id, username=None, password=None):
    """
    High-level function to fetch and parse TAXII feed.
    """
    client = SimpleTAXIIClient(url, username, password)
    
    logger.info(f"Fetching TAXII collection {collection_id} from {url}")
    stix_objects = client.get_collection_objects(collection_id)
    
    if not stix_objects:
        return []
        
    logger.info(f"Fetched {len(stix_objects)} STIX objects. Parsing...")
    indicators = extract_indicators_from_stix(stix_objects)
    
    # De-duplicate
    return list(set(indicators))
