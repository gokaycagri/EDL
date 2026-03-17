"""
SSO and ITAI middleware tests.

Verifies:
  1. SSO endpoint disabled when ITAI_MODE=false (returns 403)
  2. SSO creates session with valid JWT when ITAI_MODE=true
  3. SSO rejects invalid/expired tokens
  4. JWT verification helper function
  5. Trace ID utility function
"""

import base64
import hashlib
import hmac
import json
import time

import pytest

from threat_feed_aggregator.app import app as flask_app
from threat_feed_aggregator.middleware import itai as itai_mod


def _make_hs256_token(payload: dict, secret: str = "sso_test_secret_key") -> str:
    """Create a valid HS256 JWT for testing."""
    header = base64.urlsafe_b64encode(
        json.dumps({"alg": "HS256", "typ": "JWT"}).encode()
    ).rstrip(b"=").decode()

    payload_enc = base64.urlsafe_b64encode(
        json.dumps(payload).encode()
    ).rstrip(b"=").decode()

    sig_input = f"{header}.{payload_enc}".encode()
    signature = base64.urlsafe_b64encode(
        hmac.new(secret.encode(), sig_input, hashlib.sha256).digest()
    ).rstrip(b"=").decode()

    return f"{header}.{payload_enc}.{signature}"


# ============================================================
# SSO Disabled (Standalone Mode — default)
# ============================================================

class TestSSODisabled:
    """When ITAI_MODE is false, SSO endpoint returns 403."""

    def test_sso_returns_403_in_standalone(self, client):
        resp = client.post("/auth/sso", headers={"Authorization": "Bearer fake"})
        assert resp.status_code == 403
        assert resp.json["code"] == "SSO_DISABLED"

    def test_sso_get_not_allowed(self, client):
        resp = client.get("/auth/sso")
        assert resp.status_code == 405  # Method Not Allowed


# ============================================================
# JWT Verification (Unit Tests — no Flask app needed)
# ============================================================

class TestJWTVerification:
    """Unit tests for _verify_hs256_token."""

    def test_valid_token(self):
        token = _make_hs256_token(
            {"sub": "user1", "exp": time.time() + 3600},
            secret="my_secret",
        )
        result = itai_mod._verify_hs256_token(token, "my_secret")
        assert result is not None
        assert result["sub"] == "user1"

    def test_expired_token(self):
        token = _make_hs256_token(
            {"sub": "user1", "exp": time.time() - 3600},
            secret="my_secret",
        )
        result = itai_mod._verify_hs256_token(token, "my_secret")
        assert result is None

    def test_wrong_secret(self):
        token = _make_hs256_token(
            {"sub": "user1", "exp": time.time() + 3600},
            secret="correct_secret",
        )
        result = itai_mod._verify_hs256_token(token, "wrong_secret")
        assert result is None

    def test_malformed_token(self):
        result = itai_mod._verify_hs256_token("not.a.jwt", "secret")
        assert result is None

    def test_too_few_parts(self):
        result = itai_mod._verify_hs256_token("only.two", "secret")
        assert result is None

    def test_empty_token(self):
        result = itai_mod._verify_hs256_token("", "secret")
        assert result is None

    def test_no_expiry_is_rejected(self):
        """Tokens without exp claim are rejected for security."""
        token = _make_hs256_token({"sub": "user1"}, secret="s")
        result = itai_mod._verify_hs256_token(token, "s")
        assert result is None

    def test_preferred_username_extracted(self):
        token = _make_hs256_token(
            {"preferred_username": "admin", "sub": "uid", "exp": time.time() + 3600},
            secret="s",
        )
        result = itai_mod._verify_hs256_token(token, "s")
        assert result["preferred_username"] == "admin"


# ============================================================
# SSO Enabled (ITAI Mode) — Direct Endpoint Tests
# ============================================================

class TestSSOEnabled:
    """SSO endpoint when ITAI_MODE=true."""

    @pytest.fixture(autouse=True)
    def enable_itai_mode(self):
        """Temporarily enable ITAI mode for all tests in this class."""
        orig_mode = itai_mod.ITAI_MODE
        orig_secret = itai_mod.ITAI_JWT_SECRET
        itai_mod.ITAI_MODE = True
        itai_mod.ITAI_JWT_SECRET = "sso_test_secret_key"
        yield
        itai_mod.ITAI_MODE = orig_mode
        itai_mod.ITAI_JWT_SECRET = orig_secret

    def test_missing_bearer_token(self, client):
        resp = client.post("/auth/sso")
        assert resp.status_code == 401
        assert resp.json["code"] == "SSO_MISSING_TOKEN"

    def test_invalid_token(self, client):
        resp = client.post(
            "/auth/sso", headers={"Authorization": "Bearer invalid.token.here"}
        )
        assert resp.status_code == 401
        assert resp.json["code"] == "SSO_INVALID_TOKEN"

    def test_expired_token(self, client):
        token = _make_hs256_token({"sub": "user", "exp": time.time() - 3600})
        resp = client.post(
            "/auth/sso", headers={"Authorization": f"Bearer {token}"}
        )
        assert resp.status_code == 401

    def test_wrong_secret(self, client):
        token = _make_hs256_token(
            {"sub": "user", "exp": time.time() + 3600},
            secret="wrong_secret",
        )
        resp = client.post(
            "/auth/sso", headers={"Authorization": f"Bearer {token}"}
        )
        assert resp.status_code == 401

    def test_valid_token_creates_session(self, client):
        token = _make_hs256_token({
            "sub": "testuser",
            "preferred_username": "admin",
            "exp": time.time() + 3600,
        })
        resp = client.post(
            "/auth/sso", headers={"Authorization": f"Bearer {token}"}
        )
        assert resp.status_code == 200
        assert resp.json["status"] == "success"
        assert resp.json["data"]["session"] == "created"
        assert resp.json["data"]["username"] == "admin"

    def test_session_persists_after_sso(self, client):
        """After SSO login, subsequent requests should be authenticated."""
        token = _make_hs256_token({
            "preferred_username": "sso_user",
            "exp": time.time() + 3600,
        })
        client.post("/auth/sso", headers={"Authorization": f"Bearer {token}"})
        # Access protected endpoint without additional auth
        resp = client.get("/api/status")
        assert resp.status_code == 200

    def test_no_secret_configured(self, client):
        """If ITAI_JWT_SECRET is empty, SSO returns 500."""
        orig = itai_mod.ITAI_JWT_SECRET
        itai_mod.ITAI_JWT_SECRET = ""
        try:
            resp = client.post(
                "/auth/sso",
                headers={"Authorization": "Bearer some.valid.token"},
            )
            assert resp.status_code == 500
            assert resp.json["code"] == "SSO_NOT_CONFIGURED"
        finally:
            itai_mod.ITAI_JWT_SECRET = orig

    def test_sub_fallback_when_no_preferred_username(self, client):
        """Falls back to 'sub' if preferred_username not in token."""
        token = _make_hs256_token({
            "sub": "fallback_user",
            "exp": time.time() + 3600,
        })
        resp = client.post(
            "/auth/sso", headers={"Authorization": f"Bearer {token}"}
        )
        assert resp.status_code == 200
        assert resp.json["data"]["username"] == "fallback_user"


# ============================================================
# Trace ID (Unit Test of context var)
# ============================================================

class TestTraceIdUtility:
    """Test get_trace_id utility."""

    def test_default_is_none(self):
        assert itai_mod.get_trace_id() is None

    def test_set_and_get(self):
        itai_mod.trace_id_var.set("test-trace-id")
        assert itai_mod.get_trace_id() == "test-trace-id"
        # Reset
        itai_mod.trace_id_var.set(None)
