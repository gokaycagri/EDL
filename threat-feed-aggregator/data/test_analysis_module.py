import unittest
from unittest.mock import MagicMock, patch
import sys
import os

# Mock missing dependencies for local testing
sys.modules['werkzeug'] = MagicMock()
sys.modules['werkzeug.security'] = MagicMock()
sys.modules['flask'] = MagicMock()
sys.modules['flask_login'] = MagicMock()

# Add project root to path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from threat_feed_aggregator.services.analysis_service import _get_tags_from_sources, _calculate_risk_level, get_analysis_data

class TestAnalysisModule(unittest.TestCase):

    def test_auto_tagging(self):
        # 1. Test Feodo -> Botnet, C2
        sources = [{'source_name': 'Feodo Tracker'}]
        tags = _get_tags_from_sources(sources)
        self.assertIn('Botnet', tags)
        self.assertIn('C2', tags)

        # 2. Test URLHaus -> Malware
        sources = [{'source_name': 'URLHaus'}]
        tags = _get_tags_from_sources(sources)
        self.assertIn('Malware', tags)

        # 3. Test USOM -> Phishing
        sources = [{'source_name': 'USOM'}]
        tags = _get_tags_from_sources(sources)
        self.assertIn('Phishing', tags)

        # 4. Test Mixed
        sources = [{'source_name': 'Feodo Tracker'}, {'source_name': 'USOM'}]
        tags = _get_tags_from_sources(sources)
        self.assertIn('C2', tags)
        self.assertIn('Phishing', tags)

        # 5. Test Uncategorized
        sources = [{'source_name': 'Unknown Source'}]
        tags = _get_tags_from_sources(sources)
        self.assertIn('Uncategorized', tags)

    def test_risk_level_calculation(self):
        self.assertEqual(_calculate_risk_level(95), 'Critical')
        self.assertEqual(_calculate_risk_level(90), 'Critical')
        self.assertEqual(_calculate_risk_level(89), 'High')
        self.assertEqual(_calculate_risk_level(70), 'High')
        self.assertEqual(_calculate_risk_level(69), 'Medium')
        self.assertEqual(_calculate_risk_level(40), 'Medium')
        self.assertEqual(_calculate_risk_level(39), 'Low')
        self.assertEqual(_calculate_risk_level(0), 'Low')

    @patch('threat_feed_aggregator.services.analysis_service.get_indicators_paginated')
    @patch('threat_feed_aggregator.services.analysis_service.get_sources_for_indicators_batch')
    def test_get_analysis_data(self, mock_get_sources_batch, mock_get_paginated):
        # Mock Data
        mock_items = [
            {'indicator': '1.1.1.1', 'type': 'ip', 'country': 'US', 'risk_score': 95, 'source_count': 2, 'last_seen': '2023-01-01'},
            {'indicator': 'bad.com', 'type': 'domain', 'country': None, 'risk_score': 50, 'source_count': 1, 'last_seen': '2023-01-02'}
        ]
        mock_get_paginated.return_value = (100, 100, mock_items) # Total, Filtered, Items

        # Mock Sources Batch
        mock_get_sources_batch.return_value = {
            '1.1.1.1': [{'source_name': 'Feodo Tracker'}, {'source_name': 'URLHaus'}],
            'bad.com': [{'source_name': 'Unknown Feed'}]
        }

        # Call Service
        result = get_analysis_data(draw=1, start=0, length=10, search_value=None, order_col='risk_score', order_dir='desc')

        # Verify Structure
        self.assertEqual(result['draw'], 1)
        self.assertEqual(result['recordsTotal'], 100)
        self.assertEqual(result['data'][0]['indicator'], '1.1.1.1')
        self.assertEqual(result['data'][0]['level'], 'Critical')
        self.assertIn('Botnet', result['data'][0]['tags'])
        self.assertIn('Malware', result['data'][0]['tags'])
        
        self.assertEqual(result['data'][1]['indicator'], 'bad.com')
        self.assertEqual(result['data'][1]['level'], 'Medium')
        self.assertIn('Uncategorized', result['data'][1]['tags'])

if __name__ == '__main__':
    unittest.main()
