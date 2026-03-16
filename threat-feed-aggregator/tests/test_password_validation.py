"""Tests for password complexity validation."""
from threat_feed_aggregator.utils import validate_password_strength


class TestPasswordStrength:
    def test_valid_password(self):
        valid, msg = validate_password_strength("SecurePass1")
        assert valid is True
        assert msg == ""

    def test_too_short(self):
        valid, msg = validate_password_strength("Ab1")
        assert valid is False
        assert "8 characters" in msg

    def test_no_uppercase(self):
        valid, msg = validate_password_strength("lowercase1")
        assert valid is False
        assert "uppercase" in msg

    def test_no_lowercase(self):
        valid, msg = validate_password_strength("UPPERCASE1")
        assert valid is False
        assert "lowercase" in msg

    def test_no_digit(self):
        valid, msg = validate_password_strength("NoDigitsHere")
        assert valid is False
        assert "digit" in msg

    def test_empty_password(self):
        valid, msg = validate_password_strength("")
        assert valid is False

    def test_none_password(self):
        valid, msg = validate_password_strength(None)
        assert valid is False

    def test_exactly_min_length(self):
        valid, _ = validate_password_strength("Abcdefg1")
        assert valid is True

    def test_special_chars_allowed(self):
        valid, _ = validate_password_strength("P@ssw0rd!")
        assert valid is True
