"""
Contract tests for ITAI adapter integration.

These tests verify that endpoints the ITAI adapter depends on:
  1. Exist (not 404)
  2. Return JSON with expected structure
  3. Use correct HTTP status codes

If any of these tests fail, the ITAI adapter integration is broken.
Do NOT remove or rename these endpoints without updating the adapter.
"""

import io
import zipfile

import pytest
from unittest.mock import patch, MagicMock


@pytest.fixture
def auth_client(client):
    """Client with active session (bypasses login_required)."""
    with client.session_transaction() as sess:
        sess["logged_in"] = True
        sess["username"] = "admin"
        sess["permissions"] = {"dashboard": "rw", "system": "rw", "tools": "rw"}
    return client


# --- Helper to build mock config for api_key_required ---

MOCK_API_KEY = "contractTestKey1234567890ab"
MOCK_CONFIG = {
    "api_clients": [
        {"name": "ContractTest", "api_key": MOCK_API_KEY, "allowed_ips": []}
    ],
    "source_urls": [],
    "timezone": "UTC",
}


def api_key_headers():
    return {"Authorization": f"Bearer {MOCK_API_KEY}"}


# ============================================================
# Status & Stats Endpoints
# ============================================================

class TestStatusContract:
    """Contract: GET /api/status"""

    def test_endpoint_exists(self, auth_client):
        resp = auth_client.get("/api/status")
        assert resp.status_code != 404

    def test_returns_json(self, auth_client):
        resp = auth_client.get("/api/status")
        assert resp.content_type.startswith("application/json")

    def test_response_structure(self, auth_client):
        resp = auth_client.get("/api/status")
        data = resp.json
        assert "status" in data
        assert "timestamp" in data
        assert "data" in data
        assert "aggregation_status" in data["data"]


class TestStatusDetailedContract:
    """Contract: GET /api/status_detailed"""

    def test_endpoint_exists(self, auth_client):
        resp = auth_client.get("/api/status_detailed")
        assert resp.status_code != 404

    def test_returns_json(self, auth_client):
        resp = auth_client.get("/api/status_detailed")
        assert resp.content_type.startswith("application/json")

    def test_response_has_status(self, auth_client):
        resp = auth_client.get("/api/status_detailed")
        assert resp.json["status"] == "success"


class TestSourceStatsContract:
    """Contract: GET /api/source_stats"""

    @patch("threat_feed_aggregator.routes.api.read_config", return_value=MOCK_CONFIG)
    @patch("threat_feed_aggregator.routes.api.read_stats", return_value={})
    @patch("threat_feed_aggregator.routes.api.get_unique_indicator_count", return_value=0)
    @patch("threat_feed_aggregator.routes.api.get_indicator_counts_by_type", return_value={})
    def test_response_structure(self, mock_counts, mock_unique, mock_stats, mock_config, auth_client):
        resp = auth_client.get("/api/source_stats")
        assert resp.status_code == 200
        data = resp.json
        assert data["status"] == "success"
        assert "sources" in data["data"]
        assert "totals" in data["data"]
        assert "total" in data["data"]["totals"]


class TestScheduledJobsContract:
    """Contract: GET /api/scheduled_jobs"""

    @patch("threat_feed_aggregator.routes.api.read_config", return_value=MOCK_CONFIG)
    @patch("threat_feed_aggregator.routes.api.scheduler")
    def test_response_structure(self, mock_scheduler, mock_config, auth_client):
        mock_scheduler.get_jobs.return_value = []
        resp = auth_client.get("/api/scheduled_jobs")
        assert resp.status_code == 200
        data = resp.json
        assert data["status"] == "success"
        assert "items" in data["data"]
        assert "total" in data["data"]


class TestTrendDataContract:
    """Contract: GET /api/trend_data"""

    @patch("threat_feed_aggregator.routes.api.get_historical_stats", return_value=[])
    def test_response_structure(self, mock_stats, auth_client):
        resp = auth_client.get("/api/trend_data")
        assert resp.status_code == 200
        data = resp.json
        assert data["status"] == "success"
        assert "items" in data["data"]


class TestHistoryContract:
    """Contract: GET /api/history"""

    @patch("threat_feed_aggregator.routes.api.get_job_history", return_value=[])
    def test_response_structure(self, mock_history, auth_client):
        resp = auth_client.get("/api/history")
        assert resp.status_code == 200
        data = resp.json
        assert data["status"] == "success"
        assert "items" in data["data"]
        assert "total" in data["data"]


# ============================================================
# Action Endpoints
# ============================================================

class TestRunContract:
    """Contract: POST /api/run"""

    def test_endpoint_exists(self, auth_client):
        resp = auth_client.post("/api/run")
        assert resp.status_code != 404

    def test_returns_standard_format(self, auth_client):
        resp = auth_client.post("/api/run")
        assert resp.status_code == 200
        data = resp.json
        assert data["status"] == "success"
        assert "aggregation_status" in data["data"]


class TestRunSingleContract:
    """Contract: POST /api/run_single/<name>"""

    @patch("threat_feed_aggregator.routes.api.read_config", return_value=MOCK_CONFIG)
    def test_not_found_returns_error(self, mock_config, auth_client):
        resp = auth_client.post("/api/run_single/nonexistent")
        assert resp.status_code == 404
        assert resp.json["status"] == "error"
        assert "code" in resp.json


class TestRegenerateListsContract:
    """Contract: POST /api/regenerate_lists"""

    @patch("threat_feed_aggregator.routes.api.regenerate_edl_files", return_value=(True, "OK"))
    def test_response_structure(self, mock_regen, auth_client):
        resp = auth_client.post("/api/regenerate_lists")
        assert resp.status_code == 200
        assert resp.json["status"] == "success"


# ============================================================
# Cloud Feed Endpoints
# ============================================================

class TestCloudFeedsContract:
    """Contract: POST /api/update_ms365, update_github, update_azure"""

    @patch("threat_feed_aggregator.routes.api.process_microsoft_feeds", return_value=(True, "OK"))
    def test_ms365_success(self, mock_fn, auth_client):
        resp = auth_client.post("/api/update_ms365")
        assert resp.status_code == 200
        assert resp.json["status"] == "success"

    @patch("threat_feed_aggregator.routes.api.process_microsoft_feeds", return_value=(False, "Error"))
    def test_ms365_failure_returns_error(self, mock_fn, auth_client):
        resp = auth_client.post("/api/update_ms365")
        assert resp.status_code == 500
        assert resp.json["status"] == "error"
        assert "code" in resp.json

    @patch("threat_feed_aggregator.routes.api.process_github_feeds", return_value=(True, "OK"))
    def test_github_success(self, mock_fn, auth_client):
        resp = auth_client.post("/api/update_github")
        assert resp.status_code == 200
        assert resp.json["status"] == "success"

    @patch("threat_feed_aggregator.routes.api.process_azure_feeds", return_value=(True, "OK"))
    def test_azure_success(self, mock_fn, auth_client):
        resp = auth_client.post("/api/update_azure")
        assert resp.status_code == 200
        assert resp.json["status"] == "success"


# ============================================================
# Indicator Endpoints (API Key Auth)
# ============================================================

class TestIndicatorsContract:
    """Contract: POST/DELETE /api/indicators"""

    @patch("threat_feed_aggregator.routes.api.add_whitelist_item", return_value=(True, "Added"))
    @patch("threat_feed_aggregator.routes.api.validate_indicator", return_value=(True, "ip"))
    @patch("threat_feed_aggregator.config_manager.read_config", return_value=MOCK_CONFIG)
    @patch("threat_feed_aggregator.routes.auth.read_config", return_value=MOCK_CONFIG)
    def test_add_indicator_success(self, mock_auth_config, mock_config, mock_validate, mock_add, client):
        resp = client.post(
            "/api/indicators",
            json={"type": "whitelist", "value": "1.2.3.4"},
            headers=api_key_headers(),
        )
        assert resp.status_code == 200
        assert resp.json["status"] == "success"
        assert "data" in resp.json

    @patch("threat_feed_aggregator.config_manager.read_config", return_value=MOCK_CONFIG)
    @patch("threat_feed_aggregator.routes.auth.read_config", return_value=MOCK_CONFIG)
    def test_add_indicator_validation(self, mock_auth_config, mock_config, client):
        resp = client.post(
            "/api/indicators",
            json={},
            headers=api_key_headers(),
        )
        assert resp.status_code == 400
        assert resp.json["status"] == "error"
        assert "code" in resp.json

    @patch("threat_feed_aggregator.config_manager.read_config", return_value=MOCK_CONFIG)
    @patch("threat_feed_aggregator.routes.auth.read_config", return_value=MOCK_CONFIG)
    def test_remove_indicator_missing_value(self, mock_auth_config, mock_config, client):
        resp = client.delete(
            "/api/indicators",
            json={},
            headers=api_key_headers(),
        )
        assert resp.status_code == 400
        assert resp.json["status"] == "error"


# ============================================================
# Tools Endpoints
# ============================================================

class TestLookupContract:
    """Contract: POST /tools/api/lookup_ip, /tools/api/lookup_internal"""

    def test_lookup_ip_validation(self, auth_client):
        resp = auth_client.post("/tools/api/lookup_ip", json={})
        assert resp.status_code == 400
        assert resp.json["status"] == "error"
        assert resp.json["code"] == "VALIDATION_ERROR"

    def test_lookup_internal_validation(self, auth_client):
        resp = auth_client.post("/tools/api/lookup_internal", json={})
        assert resp.status_code == 400
        assert resp.json["status"] == "error"

    def test_lookup_ip_endpoint_exists(self, auth_client):
        resp = auth_client.post("/tools/api/lookup_ip", json={"ip": "8.8.8.8"})
        assert resp.status_code != 404


class TestDnsDedupContract:
    """Contract: POST /tools/api/dns_deduplication/*"""

    def test_delete_validation(self, auth_client):
        resp = auth_client.post(
            "/tools/api/dns_deduplication/delete", json={"indicators": []}
        )
        assert resp.status_code == 400
        assert resp.json["status"] == "error"


# ============================================================
# EDL Output Endpoints (raw — no envelope)
# ============================================================

class TestEdlOutputContract:
    """Contract: Firewall/Generic/Custom EDL endpoints return raw data."""

    def test_firewall_edl_not_found(self, client):
        resp = client.get("/api/edl/firewall/nonexistent.txt")
        assert resp.status_code == 404

    def test_firewall_edl_rejects_non_txt(self, client):
        resp = client.get("/api/edl/firewall/evil.sh")
        assert resp.status_code == 403

    @patch("threat_feed_aggregator.routes.auth.read_config", return_value=MOCK_CONFIG)
    def test_generic_edl_requires_auth(self, mock_config, client):
        """Generic EDL requires API key — no session, no key → 401."""
        resp = client.get("/api/edl/generic")
        assert resp.status_code == 401

    def test_custom_edl_not_found(self, client):
        resp = client.get("/api/edl/custom/nonexistent_token")
        assert resp.status_code == 404


# ============================================================
# Health Endpoint
# ============================================================

class TestHealthContract:
    """Contract: GET /health"""

    def test_health_returns_200(self, client):
        resp = client.get("/health")
        assert resp.status_code == 200

    def test_health_response_structure(self, client):
        resp = client.get("/health")
        data = resp.json
        assert data["status"] == "success"
        assert "version" in data["data"]
        assert data["data"]["status"] in ("healthy", "degraded")


# ============================================================
# History Clear Endpoint
# ============================================================

class TestHistoryClearContract:
    """Contract: POST /api/history/clear"""

    @patch("threat_feed_aggregator.routes.api.clear_job_history", return_value=True)
    def test_clear_success(self, mock_clear, auth_client):
        resp = auth_client.post("/api/history/clear")
        assert resp.status_code == 200
        assert resp.json["status"] == "success"

    @patch("threat_feed_aggregator.routes.api.clear_job_history", return_value=False)
    def test_clear_failure(self, mock_clear, auth_client):
        resp = auth_client.post("/api/history/clear")
        assert resp.status_code == 500
        assert resp.json["status"] == "error"


class TestLiveLogsContract:
    """Contract: GET /api/live_logs, POST /api/live_logs/clear"""

    @patch("threat_feed_aggregator.routes.api.get_live_logs", return_value=[])
    def test_logs_structure(self, mock_logs, auth_client):
        resp = auth_client.get("/api/live_logs")
        assert resp.status_code == 200
        assert "items" in resp.json["data"]

    def test_clear_logs(self, auth_client):
        resp = auth_client.post("/api/live_logs/clear")
        assert resp.status_code == 200
        assert resp.json["status"] == "success"


class TestTestFeedContract:
    """Contract: POST /api/test_feed"""

    def test_endpoint_exists(self, auth_client):
        resp = auth_client.post("/api/test_feed", json={"url": "http://test"})
        assert resp.status_code != 404

    def test_missing_payload(self, auth_client):
        resp = auth_client.post("/api/test_feed", json={})
        assert resp.status_code != 404


# ============================================================
# Backup/Restore Endpoints
# ============================================================

class TestBackupContract:
    """Contract: POST /api/backup"""

    def test_requires_auth(self, client):
        resp = client.post("/api/backup")
        assert resp.status_code == 302

    def test_rejects_get(self, auth_client):
        resp = auth_client.get("/api/backup")
        assert resp.status_code == 405

    def test_returns_zip_for_admin(self, auth_client):
        resp = auth_client.post("/api/backup")
        # May succeed with ZIP or fail (500) if data dir is empty
        assert resp.status_code in (200, 500)
        if resp.status_code == 200:
            assert "application/zip" in resp.content_type


class TestRestoreContract:
    """Contract: POST /api/restore"""

    def test_requires_auth(self, client):
        resp = client.post("/api/restore")
        assert resp.status_code == 302

    def test_requires_system_rw(self, readonly_client):
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w") as zf:
            zf.writestr("config.json", "{}")
        buf.seek(0)
        resp = readonly_client.post(
            "/api/restore",
            data={"backup_file": (buf, "test.zip")},
            content_type="multipart/form-data",
        )
        assert resp.status_code == 302


# ============================================================
# Deceptor Endpoints Contract
# ============================================================

class TestDeceptorContract:
    """Contract: POST /api/deceptor/block, /api/deceptor/unblock"""

    @patch("threat_feed_aggregator.config_manager.read_config", return_value=MOCK_CONFIG)
    @patch("threat_feed_aggregator.routes.auth.read_config", return_value=MOCK_CONFIG)
    def test_block_requires_api_key(self, mock_auth, mock_config, client):
        resp = client.post("/api/deceptor/block", json={"whblockdata": "1.1.1.1"})
        assert resp.status_code == 401

    @patch("threat_feed_aggregator.config_manager.read_config", return_value=MOCK_CONFIG)
    @patch("threat_feed_aggregator.routes.auth.read_config", return_value=MOCK_CONFIG)
    def test_unblock_requires_api_key(self, mock_auth, mock_config, client):
        resp = client.post("/api/deceptor/unblock", json={"whunblockdata": "1.1.1.1"})
        assert resp.status_code == 401

    @patch("threat_feed_aggregator.config_manager.read_config", return_value=MOCK_CONFIG)
    @patch("threat_feed_aggregator.routes.auth.read_config", return_value=MOCK_CONFIG)
    def test_unblock_skips_invalid_ip(self, mock_auth, mock_config, client):
        """Deceptor unblock returns 200 and skips invalid IPs (no retry from FortiDeceptor)."""
        resp = client.post(
            "/api/deceptor/unblock",
            json={"whunblockdata": "not-an-ip"},
            headers=api_key_headers(),
        )
        assert resp.status_code == 200
        assert "not-an-ip" in resp.json["skipped_invalid"]


# ============================================================
# Feed Health Contract
# ============================================================

class TestFeedHealthContract:
    """Contract: GET /api/feed_health"""

    def test_requires_auth(self, client):
        resp = client.get("/api/feed_health")
        assert resp.status_code == 302

    def test_returns_json(self, auth_client):
        resp = auth_client.get("/api/feed_health")
        assert resp.status_code == 200
        assert resp.content_type.startswith("application/json")
        assert resp.json["status"] == "success"


# ============================================================
# Safe List Endpoints Contract
# ============================================================

class TestSafeListContract:
    """Contract: POST /api/safe_list/add, /api/safe_list/remove"""

    @patch("threat_feed_aggregator.routes.api.add_to_safe_list", return_value=(True, "Added"))
    def test_add_valid_item(self, mock_add, auth_client):
        resp = auth_client.post("/api/safe_list/add", data={"item": "8.8.8.8"})
        assert resp.status_code == 302

    def test_add_invalid_item(self, auth_client):
        resp = auth_client.post(
            "/api/safe_list/add",
            data={"item": "not-valid!!!"},
            follow_redirects=True,
        )
        assert b"not a valid" in resp.data
