import pytest
from threat_feed_aggregator.db_manager import get_api_blacklist_items, remove_api_blacklist_item

def test_deceptor_multi_ip_block(client):
    """Test blocking multiple IPs from Deceptor in one request."""
    # Use valid key from config
    api_key = "4Sb4rLIIlEONmHo768OaLIGcTrmK9Mp6"
    test_ips = "1.1.1.1, 2.2.2.2"
    
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
    
    # Cleanup
    remove_api_blacklist_item("1.1.1.1")
    remove_api_blacklist_item("2.2.2.2")

def test_deceptor_test_string(client):
    """Test Deceptor test signals."""
    api_key = "4Sb4rLIIlEONmHo768OaLIGcTrmK9Mp6"
    response = client.post('/api/deceptor/block', 
                           headers={'X-API-KEY': api_key},
                           data={'whblockdata': '1'})
    
    assert response.status_code == 200
    assert "success" in response.get_json()['status']
