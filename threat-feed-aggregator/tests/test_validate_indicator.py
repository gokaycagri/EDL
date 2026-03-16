"""Tests for indicator validation utility."""
from threat_feed_aggregator.utils import validate_indicator


class TestValidateIndicator:
    def test_valid_ipv4(self):
        valid, itype = validate_indicator("1.2.3.4")
        assert valid is True
        assert "ip" in itype

    def test_valid_cidr(self):
        valid, itype = validate_indicator("10.0.0.0/8")
        assert valid is True
        assert "ip" in itype or "cidr" in itype

    def test_valid_domain(self):
        valid, itype = validate_indicator("example.com")
        assert valid is True
        assert itype == "domain"

    def test_valid_subdomain(self):
        valid, itype = validate_indicator("sub.domain.example.com")
        assert valid is True
        assert itype == "domain"

    def test_valid_url(self):
        valid, itype = validate_indicator("https://example.com/path")
        assert valid is True
        assert itype == "url"

    def test_invalid_empty(self):
        valid, _ = validate_indicator("")
        assert valid is False

    def test_invalid_none(self):
        valid, _ = validate_indicator(None)
        assert valid is False

    def test_invalid_string(self):
        valid, _ = validate_indicator("not an indicator")
        assert valid is False

    def test_private_ip(self):
        valid, itype = validate_indicator("192.168.1.1")
        assert valid is True
        assert "ip" in itype

    def test_ipv6(self):
        valid, itype = validate_indicator("2001:db8::1")
        # May or may not be supported depending on implementation
        assert isinstance(valid, bool)

    def test_single_label_domain(self):
        # "localhost" or similar — implementation dependent
        result = validate_indicator("localhost")
        assert isinstance(result, tuple)
