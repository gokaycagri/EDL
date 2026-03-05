import sys
# Standard Shim
try:
    import werkzeug
    if not hasattr(werkzeug, 'exceptions'):
        import werkzeug.exceptions
        sys.modules['werkzeug.exceptions'] = werkzeug.exceptions
except: pass

import pytest
from threat_feed_aggregator.db_manager import get_api_blacklist_items, remove_api_blacklist_item

def test_deceptor_multi_ip_block(client):
    """Test blocking multiple IPs from Deceptor."""
    api_key = "4Sb4rLIIlEONmHo768OaLIGcTrmK9Mp6"
    test_ips = "1.1.1.1, 2.2.2.2"
    
    # Send request using the fixed client fixture from conftest.py
    response = client.post('/api/deceptor/block', 
                           headers={'X-API-KEY': api_key},
                           data={'whblockdata': test_ips, 'expiry': '3600'})
    
    assert response.status_code == 200
    data = response.get_json()
    assert "Processed 2 indicators" in data['message']

    items = get_api_blacklist_items()
    ips_in_db = [i['item'] for i in items]
    assert "1.1.1.1" in ips_in_db
    assert "2.2.2.2" in ips_in_db
    
    remove_api_blacklist_item("1.1.1.1")
    remove_api_blacklist_item("2.2.2.2")

def test_deceptor_tagging_logic(client):
    """Verify that Deceptor IPs are tagged correctly."""
    api_key = "4Sb4rLIIlEONmHo768OaLIGcTrmK9Mp6"
    client.post('/api/deceptor/block', 
                headers={'X-API-KEY': api_key},
                data={'whblockdata': '9.9.9.9'})
    
    items = get_api_blacklist_items()
    for item in items:
        if item['item'] == "9.9.9.9":
            assert "[FortiDeceptor]" in item['comment']
    
    remove_api_blacklist_item("9.9.9.9")
