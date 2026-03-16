"""Tests for feed health monitoring service."""
import json
import os
import tempfile
import pytest


@pytest.fixture(autouse=True)
def mock_config(tmp_path, monkeypatch):
    """Provide isolated config file for feed health tests."""
    config_path = str(tmp_path / "config.json")
    with open(config_path, "w") as f:
        json.dump({"source_urls": [], "source_health": {}}, f)

    monkeypatch.setattr("threat_feed_aggregator.config_manager.CONFIG_FILE", config_path)
    monkeypatch.setattr("threat_feed_aggregator.config_manager._config_cache", None)
    monkeypatch.setattr("threat_feed_aggregator.config_manager._config_cache_mtime", 0)


class TestRecordSuccess:
    def test_resets_failure_counter(self, mock_config):
        from threat_feed_aggregator.services.feed_health import record_failure, record_success, _get_health
        from threat_feed_aggregator.config_manager import read_config

        record_failure("TestFeed", "timeout")
        record_failure("TestFeed", "timeout")
        record_success("TestFeed")

        config = read_config()
        entry = config["source_health"]["TestFeed"]
        assert entry["consecutive_failures"] == 0
        assert entry["disabled_at"] is None

    def test_noop_on_healthy_source(self, mock_config):
        from threat_feed_aggregator.services.feed_health import record_success
        from threat_feed_aggregator.config_manager import read_config

        record_success("HealthyFeed")
        config = read_config()
        # Should not create entry for never-failed sources
        assert config["source_health"].get("HealthyFeed", {}).get("consecutive_failures", 0) == 0


class TestRecordFailure:
    def test_increments_counter(self, mock_config):
        from threat_feed_aggregator.services.feed_health import record_failure
        from threat_feed_aggregator.config_manager import read_config

        record_failure("TestFeed", "Connection refused")
        config = read_config()
        assert config["source_health"]["TestFeed"]["consecutive_failures"] == 1
        assert config["source_health"]["TestFeed"]["last_error"] == "Connection refused"

    def test_auto_disables_after_threshold(self, mock_config):
        from threat_feed_aggregator.services.feed_health import record_failure, is_source_disabled

        for i in range(3):
            result = record_failure("BadFeed", f"Error {i}")

        assert result is True
        assert is_source_disabled("BadFeed") is True

    def test_no_disable_before_threshold(self, mock_config):
        from threat_feed_aggregator.services.feed_health import record_failure, is_source_disabled

        record_failure("OkFeed", "Error 1")
        record_failure("OkFeed", "Error 2")

        assert is_source_disabled("OkFeed") is False


class TestReenableSource:
    def test_reenable_clears_disabled(self, mock_config):
        from threat_feed_aggregator.services.feed_health import record_failure, reenable_source, is_source_disabled

        for _ in range(3):
            record_failure("DisabledFeed", "error")

        assert is_source_disabled("DisabledFeed") is True

        reenable_source("DisabledFeed")
        assert is_source_disabled("DisabledFeed") is False


class TestGetAllHealthStatuses:
    def test_returns_dict(self, mock_config):
        from threat_feed_aggregator.services.feed_health import get_all_health_statuses, record_failure

        record_failure("Feed1", "err")
        record_failure("Feed2", "err")

        statuses = get_all_health_statuses()
        assert "Feed1" in statuses
        assert "Feed2" in statuses
