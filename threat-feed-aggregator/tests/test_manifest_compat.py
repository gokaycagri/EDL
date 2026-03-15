"""
Manifest compatibility tests.

Verifies that all endpoints required by the ITAI adapter manifest.json
are accessible (not 404). This prevents renames or removals from silently
breaking the adapter's tool → endpoint mapping.

The TOOL_ENDPOINT_MAP below mirrors the ITAI adapter's manifest.json.
When new tools are added to the manifest, add them here too.
"""

import pytest
from unittest.mock import patch, MagicMock


# Maps: tool_name → (HTTP method, URL path)
# This must stay in sync with modules/external/EDL/manifest.json in ITAI repo.
TOOL_ENDPOINT_MAP = {
    # Status & Stats
    "get_status": ("GET", "/api/status"),
    "get_status_detailed": ("GET", "/api/status_detailed"),
    "get_source_stats": ("GET", "/api/source_stats"),
    "get_scheduled_jobs": ("GET", "/api/scheduled_jobs"),
    "get_trend_data": ("GET", "/api/trend_data"),
    "get_history": ("GET", "/api/history"),

    # Actions
    "run_aggregation": ("GET", "/api/run"),
    "run_single_source": ("GET", "/api/run_single/test"),
    "regenerate_lists": ("POST", "/api/regenerate_lists"),

    # Cloud Feeds
    "update_ms365": ("POST", "/api/update_ms365"),
    "update_github": ("POST", "/api/update_github"),
    "update_azure": ("POST", "/api/update_azure"),

    # Indicator Management (API key auth)
    "add_indicator": ("POST", "/api/indicators"),
    "remove_indicator": ("DELETE", "/api/indicators"),

    # Investigation Tools
    "lookup_ip": ("POST", "/tools/api/lookup_ip"),
    "lookup_internal": ("POST", "/tools/api/lookup_internal"),

    # DNS Dedup
    "dns_dedup_analyze": ("POST", "/tools/api/dns_deduplication/analyze"),
    "dns_dedup_delete": ("POST", "/tools/api/dns_deduplication/delete"),
    "dns_dedup_schedule": ("POST", "/tools/api/dns_deduplication/schedule"),

    # EDL Export (raw endpoints)
    "get_edl_generic": ("GET", "/api/edl/generic"),
    "get_edl_custom": ("GET", "/api/edl/custom/test_token"),

    # Deceptor (API key auth)
    "deceptor_block": ("POST", "/api/deceptor/block"),
    "deceptor_unblock": ("POST", "/api/deceptor/unblock"),

    # System
    "test_feed": ("POST", "/api/test_feed"),
    "clear_history": ("POST", "/api/history/clear"),
    "get_live_logs": ("GET", "/api/live_logs"),
    "clear_live_logs": ("POST", "/api/live_logs/clear"),

    # Analysis
    "get_filter_options": ("GET", "/analysis/filter-options"),

    # Health
    "health_check": ("GET", "/health"),
}


@pytest.fixture
def auth_client(client):
    """Client with active session."""
    with client.session_transaction() as sess:
        sess["logged_in"] = True
        sess["username"] = "admin"
        sess["permissions"] = {"dashboard": "rw", "system": "rw", "tools": "rw"}
    return client


MOCK_API_KEY = "manifestTestKey1234567890ab"
MOCK_CONFIG = {
    "api_clients": [
        {"name": "ManifestTest", "api_key": MOCK_API_KEY, "allowed_ips": []}
    ],
    "source_urls": [],
    "timezone": "UTC",
}


class TestManifestEndpointsExist:
    """Every tool in manifest.json has a reachable endpoint (not 404).

    Some endpoints may return 400/401/500 due to missing data — that's OK.
    The point is they EXIST and are routed correctly.
    """

    # Endpoints requiring session auth
    SESSION_AUTH_ENDPOINTS = {
        "get_status", "get_status_detailed", "get_source_stats",
        "get_scheduled_jobs", "get_trend_data", "get_history",
        "run_aggregation", "run_single_source", "regenerate_lists",
        "update_ms365", "update_github", "update_azure",
        "test_feed", "clear_history", "get_live_logs", "clear_live_logs",
        "get_filter_options",
        "lookup_ip", "lookup_internal",
        "dns_dedup_analyze", "dns_dedup_delete", "dns_dedup_schedule",
    }

    # Endpoints requiring API key auth
    API_KEY_ENDPOINTS = {
        "add_indicator", "remove_indicator",
        "get_edl_generic",
        "deceptor_block", "deceptor_unblock",
    }

    # Public endpoints (no auth)
    PUBLIC_ENDPOINTS = {
        "health_check", "get_edl_custom",
    }

    @pytest.mark.parametrize("tool_name", sorted(TOOL_ENDPOINT_MAP.keys()))
    @patch("threat_feed_aggregator.routes.auth.read_config", return_value=MOCK_CONFIG)
    def test_endpoint_not_404(self, mock_config, tool_name, auth_client, client):
        method, path = TOOL_ENDPOINT_MAP[tool_name]

        # Choose client based on auth requirement
        if tool_name in self.API_KEY_ENDPOINTS:
            headers = {"Authorization": f"Bearer {MOCK_API_KEY}"}
            test_client = client
        elif tool_name in self.SESSION_AUTH_ENDPOINTS:
            headers = {}
            test_client = auth_client
        else:
            headers = {}
            test_client = client

        # Make request
        if method == "GET":
            resp = test_client.get(path, headers=headers)
        elif method == "POST":
            resp = test_client.post(path, json={}, headers=headers)
        elif method == "DELETE":
            resp = test_client.delete(path, json={}, headers=headers)
        else:
            pytest.fail(f"Unknown method: {method}")

        # Some endpoints return 404 for valid business reasons (e.g. token/source
        # not found in DB). We distinguish "endpoint doesn't exist" from
        # "endpoint exists but resource not found" by checking the response body.
        if resp.status_code == 404:
            # If it's JSON with our standard format, the endpoint exists but
            # the resource wasn't found (e.g. custom list token, source name).
            # If it's HTML or has no body, the Flask route itself is missing.
            is_json = resp.content_type and "json" in resp.content_type
            assert is_json, (
                f"Tool '{tool_name}' endpoint '{method} {path}' returned 404 "
                f"with non-JSON response. Endpoint was removed or renamed — "
                f"this breaks the ITAI adapter!"
            )
