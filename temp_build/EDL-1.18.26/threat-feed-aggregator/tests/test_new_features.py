import unittest
import json
from threat_feed_aggregator.parsers import parse_json
from threat_feed_aggregator.output_formatter import format_generic

class TestNewFeatures(unittest.TestCase):
    
    def test_parse_json_nested(self):
        """Test parsing JSON with nested dot notation keys."""
        raw_data = json.dumps([
            {"id": 1, "attributes": {"ip_address": "1.1.1.1", "score": 10}},
            {"id": 2, "attributes": {"ip_address": "2.2.2.2", "score": 20}},
            {"id": 3, "attributes": {}} # Missing key
        ])
        
        # Test extraction
        results = parse_json(raw_data, key="attributes.ip_address")
        self.assertEqual(results, ["1.1.1.1", "2.2.2.2"])
        
    def test_parse_json_simple(self):
        """Test parsing JSON with simple list of objects (backward compatibility)."""
        raw_data = json.dumps([
            {"ip": "1.1.1.1"},
            {"ip": "2.2.2.2"}
        ])
        results = parse_json(raw_data, key="ip")
        self.assertEqual(results, ["1.1.1.1", "2.2.2.2"])

    def test_format_generic_csv(self):
        """Test generic output formatter for CSV."""
        data = {
            "1.1.1.1": {"type": "ip", "risk_score": 80, "country": "US"},
            "example.com": {"type": "domain", "risk_score": 90, "country": None}
        }
        
        output = format_generic(data, output_format='csv')
        # Check header
        self.assertIn("indicator,type,risk_score,country", output)
        # Check data
        self.assertIn("1.1.1.1,ip,80,US", output)
        self.assertIn("example.com,domain,90,", output)

    def test_format_generic_json(self):
        """Test generic output formatter for JSON."""
        data = {
            "1.1.1.1": {"type": "ip", "risk_score": 80, "country": "US"}
        }
        output = format_generic(data, output_format='json')
        parsed = json.loads(output)
        self.assertEqual(len(parsed), 1)
        self.assertEqual(parsed[0]['indicator'], "1.1.1.1")
        self.assertEqual(parsed[0]['risk_score'], 80)

    def test_format_generic_text_filtering(self):
        """Test generic output formatter with type filtering."""
        data = {
            "1.1.1.1": {"type": "ip"},
            "example.com": {"type": "domain"}
        }
        
        # Filter IPs only
        output = format_generic(data, include_types=['ip'], output_format='text')
        self.assertIn("1.1.1.1", output)
        self.assertNotIn("example.com", output)
