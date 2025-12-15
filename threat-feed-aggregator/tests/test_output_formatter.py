import unittest
import sys
import os

# Add the src directory to the Python path
from threat_feed_aggregator.output_formatter import format_for_palo_alto, format_for_fortinet

class TestOutputFormatter(unittest.TestCase):

    def test_format_for_palo_alto(self):
        items = {
            "item1": {"type": "ip"},
            "item2": {"type": "cidr"},
            "item3": {"type": "ip"}
        }
        expected_output = "item1\nitem2\nitem3"
        self.assertEqual(format_for_palo_alto(items), expected_output)

    def test_format_for_palo_alto_empty_list(self):
        items = {}
        expected_output = ""
        self.assertEqual(format_for_palo_alto(items), expected_output)

    def test_format_for_fortinet(self):
        items = {
            "item1": {"type": "ip"},
            "item2": {"type": "cidr"},
            "item3": {"type": "ip"}
        }
        expected_output = "item1\nitem2\nitem3"
        self.assertEqual(format_for_fortinet(items), expected_output)

    def test_format_for_fortinet_empty_list(self):
        items = {}
        expected_output = ""
        self.assertEqual(format_for_fortinet(items), expected_output)

if __name__ == '__main__':
    unittest.main()

