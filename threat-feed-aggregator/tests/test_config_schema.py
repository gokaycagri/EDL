"""Tests for Pydantic config validation."""
import pytest
from threat_feed_aggregator.config.schema import validate_config, AppConfig, SourceConfig


class TestSourceConfig:
    def test_valid_source(self):
        s = SourceConfig(name="Test", url="https://example.com/feed.txt")
        assert s.confidence == 50
        assert s.format == "text"

    def test_confidence_out_of_range(self):
        with pytest.raises(ValueError):
            SourceConfig(name="Test", url="https://x.com", confidence=150)

    def test_invalid_format(self):
        with pytest.raises(ValueError):
            SourceConfig(name="Test", url="https://x.com", format="xml")

    def test_valid_formats(self):
        for fmt in ("text", "json", "csv", "taxii"):
            s = SourceConfig(name="T", url="https://x.com", format=fmt)
            assert s.format == fmt


class TestAppConfig:
    def test_empty_config_valid(self):
        c = AppConfig()
        assert c.source_urls == []
        assert c.indicator_lifetime_days == 30

    def test_extra_fields_allowed(self):
        c = AppConfig(source_urls=[], unknown_field="ok")
        assert c.source_urls == []

    def test_full_config(self):
        c = AppConfig(
            source_urls=[{"name": "F1", "url": "https://x.com"}],
            indicator_lifetime_days=7,
            timezone="Europe/Istanbul",
            ssl_bypass_hosts=["internal.local"],
        )
        assert len(c.source_urls) == 1
        assert c.source_urls[0].name == "F1"


class TestValidateConfig:
    def test_valid_config(self):
        errors = validate_config({"source_urls": [{"name": "X", "url": "https://x.com"}]})
        assert errors == []

    def test_invalid_source_confidence(self):
        errors = validate_config({
            "source_urls": [{"name": "X", "url": "https://x.com", "confidence": 200}]
        })
        assert len(errors) > 0
        assert any("confidence" in e for e in errors)

    def test_invalid_source_format(self):
        errors = validate_config({
            "source_urls": [{"name": "X", "url": "https://x.com", "format": "yaml"}]
        })
        assert len(errors) > 0

    def test_empty_dict_valid(self):
        errors = validate_config({})
        assert errors == []

    def test_webhooks_validation(self):
        errors = validate_config({
            "webhooks": [{"url": "https://hooks.slack.com/test", "events": ["aggregation_complete"]}]
        })
        assert errors == []
