import unittest
from unittest.mock import patch, MagicMock
import sys
import os
import requests

# Add the src directory to the Python path
from threat_feed_aggregator.data_collector import fetch_data_from_url

class TestDataCollector(unittest.TestCase):

    @patch('threat_feed_aggregator.data_collector.requests.get')
    def test_fetch_data_from_url_success(self, mock_get):
        # Configure the mock to return a successful response
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.text = "line1\nline2\nline3"
        mock_response.raise_for_status = MagicMock()
        mock_get.return_value = mock_response

        # Call the function
        url = "http://example.com/success"
        result = fetch_data_from_url(url)

        # Assert the result
        self.assertEqual(result, "line1\nline2\nline3")
        mock_get.assert_called_once_with(url, timeout=30, proxies=None, auth=None)

    @patch('threat_feed_aggregator.data_collector.requests.get')
    def test_fetch_data_from_url_failure(self, mock_get):
        # Configure the mock to raise an exception
        mock_get.side_effect = requests.exceptions.RequestException("Test error")

        # Call the function
        url = "http://example.com/failure"
        result = fetch_data_from_url(url)

        # Assert the result
        self.assertIsNone(result)
        mock_get.assert_called_once_with(url, timeout=30, proxies=None, auth=None)

if __name__ == '__main__':
    unittest.main()
