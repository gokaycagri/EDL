"""Tests for webhook notification service."""
import json
from unittest.mock import patch, MagicMock
import pytest


@pytest.fixture(autouse=True)
def mock_config(monkeypatch):
    """Mock config with webhook settings."""
    test_config = {
        "webhooks": [
            {"name": "Test Hook", "url": "https://hooks.example.com/test", "events": ["aggregation_complete"]},
            {"name": "All Events", "url": "https://hooks.example.com/all", "events": []},
        ]
    }
    monkeypatch.setattr(
        "threat_feed_aggregator.services.webhook_service.read_config",
        lambda: test_config,
    )


class TestNotify:
    @patch("threat_feed_aggregator.services.webhook_service._send_webhook")
    def test_sends_matching_event(self, mock_send, mock_config):
        from threat_feed_aggregator.services.webhook_service import notify
        import time

        notify("aggregation_complete", {"count": 100})
        time.sleep(0.1)  # Wait for thread

        assert mock_send.call_count >= 1
        # Both hooks should fire: one matches event, one has empty events (matches all)
        calls = mock_send.call_args_list
        assert len(calls) == 2

    @patch("threat_feed_aggregator.services.webhook_service._send_webhook")
    def test_skips_non_matching_event(self, mock_send, mock_config):
        from threat_feed_aggregator.services.webhook_service import notify
        import time

        notify("feed_disabled", {"source": "X"})
        time.sleep(0.1)

        # Only "All Events" hook should fire (empty events = match all)
        # "Test Hook" has events=["aggregation_complete"] so it skips "feed_disabled"
        calls = mock_send.call_args_list
        assert len(calls) == 1
        assert "all" in calls[0][0][0]  # URL contains "all"


class TestSendWebhook:
    @patch("threat_feed_aggregator.services.webhook_service.requests.post")
    def test_successful_post(self, mock_post):
        from threat_feed_aggregator.services.webhook_service import _send_webhook

        mock_post.return_value = MagicMock(status_code=200)
        _send_webhook("https://hooks.example.com/test", {"event": "test"}, "TestHook")
        mock_post.assert_called_once()

    @patch("threat_feed_aggregator.services.webhook_service.requests.post")
    def test_failure_does_not_raise(self, mock_post):
        from threat_feed_aggregator.services.webhook_service import _send_webhook
        from requests.exceptions import ConnectionError

        mock_post.side_effect = ConnectionError("Connection refused")
        # Should not raise
        _send_webhook("https://hooks.example.com/test", {"event": "test"}, "FailHook")

    @patch("threat_feed_aggregator.services.webhook_service.requests.post")
    def test_timeout_configured(self, mock_post):
        from threat_feed_aggregator.services.webhook_service import _send_webhook, WEBHOOK_TIMEOUT

        mock_post.return_value = MagicMock(status_code=200)
        _send_webhook("https://x.com", {}, "T")
        _, kwargs = mock_post.call_args
        assert kwargs["timeout"] == WEBHOOK_TIMEOUT


class TestNoWebhooks:
    def test_no_webhooks_configured(self, monkeypatch):
        from threat_feed_aggregator.services.webhook_service import notify

        monkeypatch.setattr(
            "threat_feed_aggregator.services.webhook_service.read_config",
            lambda: {"webhooks": []},
        )
        # Should not raise
        notify("aggregation_complete", {})
