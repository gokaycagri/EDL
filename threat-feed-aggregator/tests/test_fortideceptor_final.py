import sys
# Standard Shim
try:
    import werkzeug
    if not hasattr(werkzeug, 'exceptions'):
        import werkzeug.exceptions
        sys.modules['werkzeug.exceptions'] = werkzeug.exceptions
except Exception:
    pass

from unittest.mock import patch

import pytest
from threat_feed_aggregator.db_manager import get_api_blacklist_items, remove_api_blacklist_item

API_KEY = "4Sb4rLIIlEONmHo768OaLIGcTrmK9Mp6"
MOCK_CONFIG = {
    "api_clients": [{"name": "Test", "api_key": API_KEY, "allowed_ips": []}],
    "indicator_lifetime_days": 30,
}


def test_deceptor_multi_ip_block(client):
    """Test blocking multiple IPs from Deceptor."""
    test_ips = "1.1.1.1, 2.2.2.2"

    with patch('threat_feed_aggregator.routes.auth.read_config', return_value=MOCK_CONFIG):
        response = client.post('/api/deceptor/block',
                               headers={'X-API-KEY': API_KEY},
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
    with patch('threat_feed_aggregator.routes.auth.read_config', return_value=MOCK_CONFIG):
        client.post('/api/deceptor/block',
                    headers={'X-API-KEY': API_KEY},
                    data={'whblockdata': '9.9.9.9'})

    items = get_api_blacklist_items()
    for item in items:
        if item['item'] == "9.9.9.9":
            assert "[FortiDeceptor]" in item['comment']

    remove_api_blacklist_item("9.9.9.9")
