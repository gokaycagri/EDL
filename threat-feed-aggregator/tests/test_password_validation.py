"""Tests for password complexity validation."""
from threat_feed_aggregator.utils import validate_password_strength


class TestPasswordStrength:
    def test_valid_password(self):
        valid, msg = validate_password_strength("SecurePassword1")
        assert valid is True
        assert msg == ""

    def test_too_short(self):
        valid, msg = validate_password_strength("Ab1")
        assert valid is False
        assert "characters" in msg

    def test_no_uppercase(self):
        valid, msg = validate_password_strength("lowercase1pass")
        assert valid is False
        assert "uppercase" in msg

    def test_no_lowercase(self):
        valid, msg = validate_password_strength("UPPERCASE1PASS")
        assert valid is False
        assert "lowercase" in msg

    def test_no_digit(self):
        valid, msg = validate_password_strength("NoDigitsHerePass")
        assert valid is False
        assert "digit" in msg

    def test_empty_password(self):
        valid, msg = validate_password_strength("")
        assert valid is False

    def test_none_password(self):
        valid, msg = validate_password_strength(None)
        assert valid is False

    def test_exactly_min_length(self):
        # 12 chars: upper + lower + digit
        valid, _ = validate_password_strength("Abcdefghij1k")
        assert valid is True

    def test_special_chars_allowed(self):
        valid, _ = validate_password_strength("P@ssw0rdSecure!")
        assert valid is True
