import unittest
import sys
import os

# Add the src directory to the Python path
from threat_feed_aggregator.output_formatter import format_for_palo_alto, format_for_fortinet

class TestOutputFormatter(unittest.TestCase):

    def test_format_for_palo_alto(self):
        items = {
            "192.168.1.1": {"type": "ip"},
            "192.168.1.2": {"type": "ip"},
            "10.0.0.0/24": {"type": "cidr"}
        }
        # 192.168.1.1 and .2 merge into nothing standard unless it's a specific block, 
        # but wait, 1.0/24 includes them? No.
        # Let's use simpler aggregation logic example
        # 1.1.1.1 and 1.1.1.0/24 -> 1.1.1.0/24
        
        items = {
            "192.168.1.0/24": {"type": "cidr"},
            "192.168.1.50": {"type": "ip"} # Inside the CIDR
        }
        expected_output = "192.168.1.0/24"
        self.assertEqual(format_for_palo_alto(items), expected_output)

    def test_format_for_palo_alto_empty_list(self):
        items = {}
        expected_output = ""
        self.assertEqual(format_for_palo_alto(items), expected_output)

    def test_format_for_fortinet(self):
        items = {
            "10.0.0.1": {"type": "ip"},
            "10.0.0.2": {"type": "ip"},
            "10.0.0.0/30": {"type": "cidr"} # Covers .0, .1, .2, .3
        }
        expected_output = "10.0.0.0/30"
        self.assertEqual(format_for_fortinet(items), expected_output)

    def test_format_for_fortinet_empty_list(self):
        items = {}
        expected_output = ""
        self.assertEqual(format_for_fortinet(items), expected_output)

if __name__ == '__main__':
    unittest.main()

