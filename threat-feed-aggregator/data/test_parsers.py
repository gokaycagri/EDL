import unittest
import sys
import os

# Add the src directory to the Python path
from threat_feed_aggregator.parsers import parse_text, parse_json, parse_csv

class TestParsers(unittest.TestCase):

    def test_parse_text(self):
        data = "item1\nitem2\n# comment\nitem3"
        self.assertEqual(parse_text(data), ["item1", "item2", "item3"])

    def test_parse_json_list(self):
        data = '["item1", "item2", "item3"]'
        self.assertEqual(parse_json(data), ["item1", "item2", "item3"])

    def test_parse_json_objects(self):
        data = '[{"indicator": "item1"}, {"indicator": "item2"}]'
        self.assertEqual(parse_json(data, key="indicator"), ["item1", "item2"])

    def test_parse_csv(self):
        data = "item1,desc1\nitem2,desc2"
        self.assertEqual(parse_csv(data, column=0), ["item1", "item2"])

    def test_parse_csv_different_column(self):
        data = "desc1,item1\ndesc2,item2"
        self.assertEqual(parse_csv(data, column=1), ["item1", "item2"])

if __name__ == '__main__':
    unittest.main()

