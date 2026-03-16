import pytest
import json
from datetime import UTC, datetime
from unittest.mock import patch, MagicMock
from threat_feed_aggregator.repositories.whitelist_repo import add_api_blacklist_item, get_api_blacklist_item_by_value, remove_api_blacklist_item

def test_get_api_blacklist_item_by_value_logic(app):
    """Verifies that we can retrieve a specific blacklist item by its value."""
    test_ip = "1.2.3.4"
    test_comment = "Test Block"
    
    with app.app_context():
        # Cleanup first
        remove_api_blacklist_item(test_ip)
        
        # Add item
        success, msg = add_api_blacklist_item(test_ip, comment=test_comment, source="FortiDeceptor")
        assert success is True
        
        # Retrieve item
        item = get_api_blacklist_item_by_value(test_ip)
        assert item is not None
        assert item['item'] == test_ip
        assert "[FortiDeceptor]" in item['comment']
        assert test_comment in item['comment']
        
        # Cleanup
        remove_api_blacklist_item(test_ip)

def test_lookup_internal_endpoint_integration(client, app):
    """Verifies that the API returns both global feed sources and blacklist sources."""
    test_ip = "13.219.1.233"
    
    # Mock data for sources from global feeds
    mock_global_sources = [
        {'source_name': 'CINSSCORE-BANLIST', 'last_seen': '2026-03-01T10:00:00Z'}
    ]
    
    # Mock data for blacklist entry
    mock_blacklist_item = {
        'item': test_ip,
        'added_at': '2026-03-04T12:00:00Z',
        'comment': '[FortiDeceptor] Hacker detected on Sydney Honeypot'
    }

    # Bypassing login check for the test client
    with client.session_transaction() as sess:
        sess['logged_in'] = True
        sess['username'] = 'admin'

    with patch('threat_feed_aggregator.routes.tools.get_sources_for_indicator', return_value=mock_global_sources.copy()), 
         patch('threat_feed_aggregator.routes.tools.get_api_blacklist_item_by_value', return_value=mock_blacklist_item):
        
        response = client.post('/tools/api/lookup_internal', 
                                data=json.dumps({'indicator': test_ip}),
                                content_type='application/json')
        
        assert response.status_code == 200
        data = response.get_json()
        assert data['success'] is True
        
        sources = data['sources']
        # Should have 2 sources now (1 global + 1 blacklist)
        assert len(sources) == 2
        
        # Blacklist item (FortiDeceptor) should be first (index 0)
        assert sources[0]['source_name'] == 'FortiDeceptor'
        assert 'Hacker detected' in sources[0]['comment']
        
        # Global source should be second (index 1)
        assert sources[1]['source_name'] == 'CINSSCORE-BANLIST'

def test_lookup_internal_no_blacklist_match(client, app):
    """Verifies that the API works correctly when item is only in global feeds."""
    test_ip = "8.8.8.8"
    mock_global_sources = [{'source_name': 'Google-Safe', 'last_seen': '2026-03-01T10:00:00Z'}]
    
    with client.session_transaction() as sess:
        sess['logged_in'] = True
        sess['username'] = 'admin'

    with patch('threat_feed_aggregator.routes.tools.get_sources_for_indicator', return_value=mock_global_sources), 
         patch('threat_feed_aggregator.routes.tools.get_api_blacklist_item_by_value', return_value=None):
        
        response = client.post('/tools/api/lookup_internal', 
                                data=json.dumps({'indicator': test_ip}),
                                content_type='application/json')
        
        data = response.get_json()
        assert data['success'] is True
        assert len(data['sources']) == 1
        assert data['sources'][0]['source_name'] == 'Google-Safe'
