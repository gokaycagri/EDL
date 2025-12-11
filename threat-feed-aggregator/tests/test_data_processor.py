import unittest
from unittest.mock import patch, MagicMock
from datetime import datetime, timezone
from threat_feed_aggregator.data_processor import process_data

class TestDataProcessor(unittest.TestCase):

    @patch('threat_feed_aggregator.data_processor.upsert_indicators_bulk')
    def test_process_data_empty_input(self, mock_upsert):
        count = process_data("", data_format="text")
        self.assertEqual(count, 0)
        mock_upsert.assert_not_called()

    @patch('threat_feed_aggregator.data_processor.upsert_indicators_bulk')
    def test_process_data_add_new_items(self, mock_upsert):
        raw_data = "item1\nitem2"
        count = process_data(raw_data, data_format="text")
        self.assertEqual(count, 2)
        mock_upsert.assert_called_once()
        # Verify that upsert was called with correct data
        args, _ = mock_upsert.call_args
        self.assertIn("item1", args[0])
        self.assertIn("item2", args[0])

    @patch('threat_feed_aggregator.data_processor.upsert_indicators_bulk')
    def test_process_data_with_comments_and_empty_lines(self, mock_upsert):
        raw_data = "# comment\nitem1\n\nitem2\n  # another comment"
        count = process_data(raw_data, data_format="text")
        self.assertEqual(count, 2)
        mock_upsert.assert_called_once()
        args, _ = mock_upsert.call_args
        self.assertIn("item1", args[0])
        self.assertIn("item2", args[0])
        self.assertNotIn("# comment", args[0])

if __name__ == '__main__':
    unittest.main()