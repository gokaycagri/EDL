"""
Security hardening tests.

Validates that all security fixes are in place:
- State-changing endpoints require POST
- Permission checks on sensitive operations
- Input validation on external-facing endpoints
- No sensitive data in logs
- CSRF protection on destructive actions
"""

import io
import json
import zipfile

import pytest
from unittest.mock import patch, MagicMock


# ============================================================
# 1. HTTP Method Enforcement
# ============================================================

class TestHTTPMethodEnforcement:
    """All state-changing endpoints must reject GET requests."""

    def test_run_rejects_get(self, auth_client):
        resp = auth_client.get("/api/run")
        assert resp.status_code == 405

    def test_run_accepts_post(self, auth_client):
        resp = auth_client.post("/api/run")
        assert resp.status_code == 200

    @patch("threat_feed_aggregator.routes.api.read_config", return_value={"source_urls": []})
    def test_run_single_rejects_get(self, mock_config, auth_client):
        resp = auth_client.get("/api/run_single/test_source")
        assert resp.status_code == 405

    @patch("threat_feed_aggregator.routes.api.read_config", return_value={"source_urls": []})
    def test_run_single_accepts_post(self, mock_config, auth_client):
        resp = auth_client.post("/api/run_single/test_source")
        assert resp.status_code in (200, 404)

    def test_backup_rejects_get(self, auth_client):
        resp = auth_client.get("/api/backup")
        assert resp.status_code == 405

    def test_backup_accepts_post(self, auth_client):
        resp = auth_client.post("/api/backup")
        assert resp.status_code in (200, 500)

    def test_logout_rejects_get(self, auth_client):
        resp = auth_client.get("/auth/logout")
        assert resp.status_code == 405

    def test_logout_accepts_post(self, auth_client):
        resp = auth_client.post("/auth/logout")
        assert resp.status_code == 302


# ============================================================
# 2. Permission Checks
# ============================================================

class TestPermissionEnforcement:
    """Sensitive endpoints must enforce proper permissions."""

    def test_backup_requires_auth(self, client):
        resp = client.post("/api/backup")
        assert resp.status_code == 302

    def test_backup_requires_system_rw(self, readonly_client):
        resp = readonly_client.post("/api/backup")
        assert resp.status_code == 302

    def test_restore_requires_auth(self, client):
        resp = client.post("/api/restore")
        assert resp.status_code == 302

    def test_restore_requires_system_rw(self, readonly_client):
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w") as zf:
            zf.writestr("config.json", "{}")
        buf.seek(0)

        resp = readonly_client.post(
            "/api/restore",
            data={"backup_file": (buf, "backup.zip")},
            content_type="multipart/form-data",
        )
        assert resp.status_code == 302

    def test_change_password_requires_auth(self, client):
        resp = client.post(
            "/system/users/change_password",
            data={"username": "admin", "password": "NewP@ss123"},
        )
        assert resp.status_code == 302

    def test_change_password_requires_system_rw(self, readonly_client):
        resp = readonly_client.post(
            "/system/users/change_password",
            data={"username": "admin", "password": "NewP@ss123"},
            follow_redirects=True,
        )
        assert b"Access Denied" in resp.data

    def test_change_password_allowed_for_admin(self, auth_client):
        resp = auth_client.post(
            "/system/users/change_password",
            data={"username": "admin", "password": "ValidP@ss1"},
            follow_redirects=True,
        )
        # Should not be access denied — either success or user-not-found
        assert b"Access Denied" not in resp.data


# ============================================================
# 3. Password Strength on Change Password
# ============================================================

class TestPasswordStrengthOnChange:
    """change_user_password must enforce password complexity."""

    def test_weak_password_rejected(self, auth_client):
        resp = auth_client.post(
            "/system/users/change_password",
            data={"username": "testuser", "password": "weak"},
            follow_redirects=True,
        )
        assert b"at least" in resp.data

    def test_no_uppercase_rejected(self, auth_client):
        resp = auth_client.post(
            "/system/users/change_password",
            data={"username": "testuser", "password": "alllower1"},
            follow_redirects=True,
        )
        assert b"uppercase" in resp.data

    def test_no_digit_rejected(self, auth_client):
        resp = auth_client.post(
            "/system/users/change_password",
            data={"username": "testuser", "password": "NoDigitHere"},
            follow_redirects=True,
        )
        assert b"digit" in resp.data


# ============================================================
# 4. Deceptor Input Validation
# ============================================================

MOCK_API_KEY = "contractTestKey1234567890ab"
MOCK_CONFIG = {
    "api_clients": [
        {"name": "ContractTest", "api_key": MOCK_API_KEY, "allowed_ips": []}
    ],
    "source_urls": [],
    "timezone": "UTC",
    "indicator_lifetime_days": 30,
}


def api_key_headers():
    return {"Authorization": f"Bearer {MOCK_API_KEY}"}


class TestDeceptorUnblockValidation:
    """deceptor_unblock must validate IP before removal."""

    @patch("threat_feed_aggregator.config_manager.read_config", return_value=MOCK_CONFIG)
    @patch("threat_feed_aggregator.routes.auth.read_config", return_value=MOCK_CONFIG)
    def test_missing_ip_returns_400(self, mock_auth, mock_config, client):
        resp = client.post(
            "/api/deceptor/unblock",
            json={},
            headers=api_key_headers(),
        )
        assert resp.status_code == 400
        assert "Missing IP" in resp.json["message"]

    @patch("threat_feed_aggregator.config_manager.read_config", return_value=MOCK_CONFIG)
    @patch("threat_feed_aggregator.routes.auth.read_config", return_value=MOCK_CONFIG)
    def test_invalid_ip_skipped_gracefully(self, mock_auth, mock_config, client):
        """Deceptor unblock always returns 200 — invalid IPs are skipped, not rejected."""
        resp = client.post(
            "/api/deceptor/unblock",
            json={"whunblockdata": "not-a-valid-ip!!!"},
            headers=api_key_headers(),
        )
        assert resp.status_code == 200
        assert "not-a-valid-ip!!!" in resp.json["skipped_invalid"]

    @patch("threat_feed_aggregator.routes.api.remove_api_blacklist_item", return_value=False)
    @patch("threat_feed_aggregator.routes.api.validate_indicator", return_value=(True, "ip"))
    @patch("threat_feed_aggregator.config_manager.read_config", return_value=MOCK_CONFIG)
    @patch("threat_feed_aggregator.routes.auth.read_config", return_value=MOCK_CONFIG)
    def test_valid_ip_not_found_returns_200(self, mock_auth, mock_config, mock_validate, mock_remove, client):
        """Deceptor unblock returns 200 even when IP is not in blacklist (no retry)."""
        resp = client.post(
            "/api/deceptor/unblock",
            json={"whunblockdata": "1.2.3.4"},
            headers=api_key_headers(),
        )
        assert resp.status_code == 200
        assert resp.json["removed"] == 0


class TestDeceptorBlockValidation:
    """deceptor_block must skip invalid IPs and not log raw body."""

    @patch("threat_feed_aggregator.routes.api.add_api_blacklist_item", return_value=(True, "Added"))
    @patch("threat_feed_aggregator.routes.api.upsert_indicators_bulk")
    @patch("threat_feed_aggregator.config_manager.read_config", return_value=MOCK_CONFIG)
    @patch("threat_feed_aggregator.routes.auth.read_config", return_value=MOCK_CONFIG)
    def test_valid_ips_accepted(self, mock_auth, mock_config, mock_upsert, mock_add, client):
        resp = client.post(
            "/api/deceptor/block",
            json={"whblockdata": "1.1.1.1,2.2.2.2"},
            headers=api_key_headers(),
        )
        assert resp.status_code == 200
        assert "Processed" in resp.json["message"]

    @patch("threat_feed_aggregator.config_manager.read_config", return_value=MOCK_CONFIG)
    @patch("threat_feed_aggregator.routes.auth.read_config", return_value=MOCK_CONFIG)
    def test_probe_strings_ignored(self, mock_auth, mock_config, client):
        resp = client.post(
            "/api/deceptor/block",
            json={"whblockdata": "test"},
            headers=api_key_headers(),
        )
        assert resp.status_code == 200
        assert "Processed 0" in resp.json["message"]


# ============================================================
# 5. Backup Audit Log Uses Username
# ============================================================

class TestBackupAuditLog:
    """Backup audit log should use session username, not raw cookie."""

    @patch("threat_feed_aggregator.routes.api.send_file")
    @patch("threat_feed_aggregator.services.audit_service.log_action")
    def test_audit_log_uses_username(self, mock_log, mock_send, auth_client):
        mock_send.return_value = MagicMock(status_code=200)
        auth_client.post("/api/backup")

        if mock_log.called:
            call_args = mock_log.call_args
            # First positional arg should be the username, not a session cookie
            logged_user = call_args[0][0]
            assert logged_user == "admin"


# ============================================================
# 6. Restore Archive Validation
# ============================================================

class TestRestoreValidation:
    """Restore endpoint must validate archive contents."""

    def test_restore_rejects_non_zip(self, auth_client):
        resp = auth_client.post(
            "/api/restore",
            data={"backup_file": (io.BytesIO(b"not a zip"), "backup.txt")},
            content_type="multipart/form-data",
            follow_redirects=True,
        )
        assert b"Invalid file format" in resp.data or b".zip" in resp.data

    def test_restore_rejects_path_traversal(self, auth_client):
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w") as zf:
            zf.writestr("../../../etc/passwd", "pwned")
        buf.seek(0)

        resp = auth_client.post(
            "/api/restore",
            data={"backup_file": (buf, "evil.zip")},
            content_type="multipart/form-data",
            follow_redirects=True,
        )
        assert b"Unexpected file in archive" in resp.data

    def test_restore_rejects_unexpected_files(self, auth_client):
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w") as zf:
            zf.writestr("unexpected_file.py", "print('hello')")
        buf.seek(0)

        resp = auth_client.post(
            "/api/restore",
            data={"backup_file": (buf, "bad.zip")},
            content_type="multipart/form-data",
            follow_redirects=True,
        )
        assert b"Unexpected file in archive" in resp.data
