"""Tests for DNS deduplication service."""
import pytest
from threat_feed_aggregator.services.dns_deduplication import extract_domain


class TestExtractDomain:
    def test_plain_domain(self):
        assert extract_domain("example.com", "domain") == "example.com"

    def test_url_with_scheme(self):
        assert extract_domain("https://example.com/path", "url") == "example.com"

    def test_url_with_port(self):
        assert extract_domain("http://example.com:8080/path", "url") == "example.com"

    def test_url_without_scheme(self):
        # urlparse can't parse this properly, should return None
        result = extract_domain("example.com/path", "url")
        # urlparse without scheme puts everything in path, hostname is None
        assert result is None

    def test_malformed_url_returns_none(self):
        result = extract_domain("not a url at all", "url")
        assert result is None

    def test_ip_type_passthrough(self):
        assert extract_domain("1.2.3.4", "ip") == "1.2.3.4"

    def test_cidr_type_passthrough(self):
        assert extract_domain("10.0.0.0/8", "cidr") == "10.0.0.0/8"

    def test_empty_string(self):
        result = extract_domain("", "url")
        assert result is None

    def test_ftp_url(self):
        assert extract_domain("ftp://files.example.com/data", "url") == "files.example.com"
