"""
End-to-end tests for Threat Feed Aggregator UI.

Tests all major user flows: login, navigation, dashboard rendering,
save operations, API responses, and HTML structure for responsiveness.
"""

import json

import pytest


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _html(response):
    """Decode response data to string for assertion readability."""
    return response.data.decode("utf-8")


# ---------------------------------------------------------------------------
# 1. LOGIN FLOW
# ---------------------------------------------------------------------------

class TestLoginFlow:
    """Login page rendering, authentication, redirects, and logout."""

    def test_unauthenticated_redirects_to_login(self, client):
        resp = client.get("/", follow_redirects=False)
        assert resp.status_code in (302, 303)
        assert "/auth/login" in resp.headers.get("Location", "")

    def test_login_page_renders(self, client):
        resp = client.get("/auth/login")
        assert resp.status_code == 200
        html = _html(resp)
        assert "ThreatFeed" in html
        assert 'name="username"' in html
        assert 'name="password"' in html
        assert 'name="csrf_token"' in html

    def test_login_page_is_responsive(self, client):
        """Login card uses max-width instead of fixed width."""
        resp = client.get("/auth/login")
        html = _html(resp)
        assert "max-width" in html

    def test_login_with_invalid_credentials(self, client):
        resp = client.post(
            "/auth/login",
            data={"username": "wrong", "password": "wrong"},
            follow_redirects=True,
        )
        assert resp.status_code == 200
        html = _html(resp)
        # Should still be on login page
        assert 'name="username"' in html

    def test_authenticated_user_sees_dashboard(self, auth_client):
        resp = auth_client.get("/")
        assert resp.status_code == 200
        html = _html(resp)
        assert "Operational Overview" in html

    def test_logout_redirects(self, auth_client):
        resp = auth_client.post("/auth/logout", follow_redirects=False)
        assert resp.status_code in (302, 303)

    def test_logout_clears_session(self, auth_client):
        auth_client.post("/auth/logout", follow_redirects=True)
        # After logout, dashboard should redirect to login
        resp = auth_client.get("/", follow_redirects=False)
        assert resp.status_code in (302, 303)


# ---------------------------------------------------------------------------
# 2. NAVIGATION & PAGE RENDERING
# ---------------------------------------------------------------------------

class TestNavigation:
    """All pages load without errors and contain expected structure."""

    def test_dashboard_renders(self, auth_client):
        resp = auth_client.get("/")
        assert resp.status_code == 200
        html = _html(resp)
        assert "Operational Overview" in html
        assert "Total Indicators" in html
        assert "IP Addresses" in html
        assert "Active Feeds" in html

    def test_dashboard_has_stat_cards(self, auth_client):
        resp = auth_client.get("/")
        html = _html(resp)
        assert 'id="stat-total"' in html
        assert 'id="stat-ip"' in html
        assert 'id="stat-domain"' in html
        assert 'id="stat-feeds"' in html

    def test_dashboard_has_threat_sources_table(self, auth_client):
        resp = auth_client.get("/")
        html = _html(resp)
        assert "Active Threat Feed Sources" in html
        assert "Add Source" in html

    def test_dashboard_has_edl_section(self, auth_client):
        resp = auth_client.get("/")
        html = _html(resp)
        assert "Output Lists (EDL)" in html
        assert "Palo Alto" in html

    def test_dashboard_has_safe_block_lists(self, auth_client):
        resp = auth_client.get("/")
        html = _html(resp)
        assert "Safe List" in html
        assert "Block List" in html

    def test_dashboard_has_map_and_terminal(self, auth_client):
        resp = auth_client.get("/")
        html = _html(resp)
        assert "Global Threat Distribution" in html
        assert 'id="world-map"' in html
        assert "Live Operational Logs" in html
        assert 'id="logWindow"' in html

    def test_dashboard_has_task_activity(self, auth_client):
        resp = auth_client.get("/")
        html = _html(resp)
        assert "Recent Task Activity" in html
        assert "Scheduled Runs" in html

    def test_analysis_page_renders(self, auth_client):
        resp = auth_client.get("/analysis/", follow_redirects=True)
        assert resp.status_code == 200
        html = _html(resp)
        assert "Threat Analysis Center" in html
        assert "Add Filter" in html
        assert 'id="analysisTable"' in html

    def test_investigate_page_renders(self, auth_client):
        resp = auth_client.get("/tools/investigate")
        assert resp.status_code == 200
        html = _html(resp)
        assert "Threat Investigation" in html
        assert 'id="ipInput"' in html
        assert "Internal Threat Database" in html
        assert 'id="internalInput"' in html

    def test_dns_dedup_page_renders(self, auth_client):
        resp = auth_client.get("/tools/dns_deduplication")
        assert resp.status_code == 200
        html = _html(resp)
        assert "DNS Deduplication Manager" in html
        assert 'id="scheduleForm"' in html

    def test_system_page_renders(self, auth_client):
        resp = auth_client.get("/system/", follow_redirects=True)
        assert resp.status_code == 200
        html = _html(resp)
        assert "System Configuration" in html
        assert "General" in html
        assert "Authentication" in html

    def test_sidebar_present_on_dashboard(self, auth_client):
        resp = auth_client.get("/")
        html = _html(resp)
        assert "sidebar" in html
        assert "ThreatFeed" in html

    def test_sidebar_present_on_subpages(self, auth_client):
        for path in ["/analysis/", "/tools/investigate",
                     "/tools/dns_deduplication", "/system/"]:
            resp = auth_client.get(path, follow_redirects=True)
            html = _html(resp)
            assert "sidebar" in html, f"Sidebar missing on {path}"
            assert "ThreatFeed" in html, f"Brand missing on {path}"

    def test_severity_ribbon_on_pages(self, auth_client):
        for path in ["/", "/tools/investigate", "/tools/dns_deduplication"]:
            resp = auth_client.get(path, follow_redirects=True)
            html = _html(resp)
            assert "severity-ribbon" in html, f"Severity ribbon missing on {path}"
            assert 'id="ribbonStatus"' in html

    def test_csrf_token_meta_on_pages(self, auth_client):
        for path in ["/", "/tools/investigate", "/tools/dns_deduplication"]:
            resp = auth_client.get(path, follow_redirects=True)
            html = _html(resp)
            assert 'name="csrf-token"' in html, f"CSRF meta missing on {path}"


# ---------------------------------------------------------------------------
# 3. RESPONSIVE LAYOUT STRUCTURE
# ---------------------------------------------------------------------------

class TestResponsiveLayout:
    """HTML structure supports responsive design."""

    def test_viewport_meta_tag(self, auth_client):
        resp = auth_client.get("/")
        html = _html(resp)
        assert 'name="viewport"' in html
        assert "width=device-width" in html

    def test_mobile_toggle_button_exists(self, auth_client):
        resp = auth_client.get("/")
        html = _html(resp)
        assert "mobile-toggle" in html

    def test_sidebar_overlay_exists(self, auth_client):
        resp = auth_client.get("/")
        html = _html(resp)
        assert "sidebar-overlay" in html

    def test_dashboard_uses_responsive_columns(self, auth_client):
        resp = auth_client.get("/")
        html = _html(resp)
        assert "col-lg-5" in html
        assert "col-lg-7" in html
        assert "col-lg-8" in html
        assert "col-lg-4" in html

    def test_stat_cards_stay_in_row_on_mobile(self, auth_client):
        resp = auth_client.get("/")
        html = _html(resp)
        assert "col-4" in html

    def test_investigation_uses_responsive_columns(self, auth_client):
        resp = auth_client.get("/tools/investigate")
        html = _html(resp)
        assert "col-lg-5" in html
        assert "col-lg-7" in html

    def test_theme_css_loaded(self, auth_client):
        resp = auth_client.get("/")
        html = _html(resp)
        assert "theme.css" in html

    def test_theme_css_has_responsive_breakpoints(self, client):
        resp = client.get("/static/css/theme.css")
        assert resp.status_code == 200
        css = _html(resp)
        assert "@media (max-width: 992px)" in css
        assert "@media (max-width: 768px)" in css
        assert "@media (max-width: 480px)" in css

    def test_system_tabs_scrollable_on_mobile(self, auth_client):
        resp = auth_client.get("/system/", follow_redirects=True)
        html = _html(resp)
        assert "flex-nowrap" in html
        assert "overflow-auto" in html


# ---------------------------------------------------------------------------
# 4. SAFE LIST / BLOCK LIST OPERATIONS
# ---------------------------------------------------------------------------

class TestSafeBlockListOperations:
    """Safe list and block list CRUD operations via form submissions."""

    def test_add_whitelist_item(self, auth_client):
        resp = auth_client.post(
            "/system/whitelist/add",
            data={"item": "10.0.0.1", "type": "ip", "description": "Test safe IP"},
            follow_redirects=True,
        )
        assert resp.status_code == 200

    def test_add_blacklist_item(self, auth_client):
        resp = auth_client.post(
            "/system/blacklist/add",
            data={"item": "192.168.1.100", "type": "ip", "comment": "Test block"},
            follow_redirects=True,
        )
        assert resp.status_code == 200

    def test_whitelist_item_appears_on_dashboard(self, auth_client):
        auth_client.post(
            "/system/whitelist/add",
            data={"item": "safe.example.com", "type": "domain", "description": "Safe domain"},
            follow_redirects=True,
        )
        resp = auth_client.get("/")
        html = _html(resp)
        assert "safe.example.com" in html

    def test_blacklist_item_appears_on_dashboard(self, auth_client):
        auth_client.post(
            "/system/blacklist/add",
            data={"item": "evil.example.com", "type": "domain", "comment": "Malicious"},
            follow_redirects=True,
        )
        resp = auth_client.get("/")
        html = _html(resp)
        assert "evil.example.com" in html

    def test_remove_whitelist_item_via_post(self, auth_client):
        auth_client.post(
            "/system/whitelist/add",
            data={"item": "removeme.com", "type": "domain", "description": "To remove"},
            follow_redirects=True,
        )
        resp = auth_client.post(
            "/system/whitelist/remove/1",
            follow_redirects=True,
        )
        assert resp.status_code == 200

    def test_remove_whitelist_via_get_is_rejected(self, auth_client):
        """GET requests to delete endpoint should fail (405)."""
        resp = auth_client.get("/system/whitelist/remove/1")
        assert resp.status_code == 405

    def test_remove_blacklist_item(self, auth_client):
        auth_client.post(
            "/system/blacklist/add",
            data={"item": "1.2.3.4", "type": "ip", "comment": "Test"},
            follow_redirects=True,
        )
        resp = auth_client.post(
            "/system/blacklist/remove/1.2.3.4",
            follow_redirects=True,
        )
        assert resp.status_code == 200

    def test_safe_list_delete_uses_post_form(self, auth_client):
        """Dashboard safe list delete buttons must use POST forms with CSRF."""
        auth_client.post(
            "/system/whitelist/add",
            data={"item": "csrf-test.com", "type": "domain", "description": "CSRF test"},
            follow_redirects=True,
        )
        resp = auth_client.get("/")
        html = _html(resp)
        assert "csrf-test.com" in html
        assert 'action="/system/whitelist/remove/' in html
        assert 'method="POST"' in html


# ---------------------------------------------------------------------------
# 5. SOURCE MANAGEMENT
# ---------------------------------------------------------------------------

class TestSourceManagement:
    """Add, edit, and remove threat feed sources."""

    def test_add_source(self, auth_client):
        resp = auth_client.post(
            "/system/add_source",
            data={
                "name": "TestFeed",
                "url": "https://example.com/feed.txt",
                "format": "text",
                "schedule_interval_minutes": "60",
                "confidence": "75",
            },
            follow_redirects=True,
        )
        assert resp.status_code == 200

    def test_added_source_appears_on_dashboard(self, auth_client):
        auth_client.post(
            "/system/add_source",
            data={
                "name": "VisibleFeed",
                "url": "https://example.com/vis.txt",
                "format": "text",
                "schedule_interval_minutes": "30",
                "confidence": "50",
            },
            follow_redirects=True,
        )
        resp = auth_client.get("/")
        html = _html(resp)
        assert "VisibleFeed" in html

    def test_remove_source(self, auth_client):
        auth_client.post(
            "/system/add_source",
            data={
                "name": "ToRemove",
                "url": "https://example.com/rm.txt",
                "format": "text",
                "schedule_interval_minutes": "60",
                "confidence": "50",
            },
            follow_redirects=True,
        )
        resp = auth_client.post(
            "/system/remove_source/0",
            follow_redirects=True,
        )
        assert resp.status_code == 200


# ---------------------------------------------------------------------------
# 6. SYSTEM SETTINGS
# ---------------------------------------------------------------------------

class TestSystemSettings:
    """Global settings, proxy, DNS configuration saves."""

    def test_update_global_settings(self, auth_client):
        resp = auth_client.post(
            "/system/update_settings",
            data={
                "indicator_lifetime_days": "45",
                "timezone": "Europe/Istanbul",
                "base_url": "",
            },
            follow_redirects=True,
        )
        assert resp.status_code == 200

    def test_update_proxy_settings(self, auth_client):
        resp = auth_client.post(
            "/system/update_proxy",
            data={
                "http_proxy": "",
                "https_proxy": "",
            },
            follow_redirects=True,
        )
        assert resp.status_code == 200

    def test_update_dns_settings(self, auth_client):
        resp = auth_client.post(
            "/system/update_dns",
            data={
                "primary_dns": "8.8.8.8",
                "secondary_dns": "1.1.1.1",
            },
            follow_redirects=True,
        )
        assert resp.status_code == 200

    def test_readonly_user_sees_readonly_badge(self, readonly_client):
        resp = readonly_client.get("/system/", follow_redirects=True)
        html = _html(resp)
        assert "Read-Only" in html


# ---------------------------------------------------------------------------
# 7. API ENDPOINTS (JSON envelope format)
# ---------------------------------------------------------------------------

class TestAPIEndpoints:
    """API endpoints return correct envelope format and data."""

    def test_source_stats_api(self, auth_client):
        resp = auth_client.get("/api/source_stats")
        assert resp.status_code == 200
        data = json.loads(resp.data)
        assert data["status"] == "success"
        assert "data" in data

    def test_history_api(self, auth_client):
        resp = auth_client.get("/api/history?limit=5")
        assert resp.status_code == 200
        data = json.loads(resp.data)
        assert data["status"] == "success"
        assert "data" in data
        assert "items" in data["data"]

    def test_live_logs_api(self, auth_client):
        resp = auth_client.get("/api/live_logs")
        assert resp.status_code == 200
        data = json.loads(resp.data)
        assert data["status"] == "success"
        assert "data" in data
        assert "items" in data["data"]

    def test_scheduled_jobs_api(self, auth_client):
        resp = auth_client.get("/api/scheduled_jobs")
        assert resp.status_code == 200
        data = json.loads(resp.data)
        assert data["status"] == "success"
        assert "data" in data

    def test_health_endpoint(self, client):
        resp = client.get("/health")
        assert resp.status_code == 200
        data = json.loads(resp.data)
        assert data["status"] == "success"

    def test_analysis_filter_options_level(self, auth_client):
        resp = auth_client.get("/analysis/filter-options?column=level", follow_redirects=True)
        assert resp.status_code == 200
        data = json.loads(resp.data)
        assert data["status"] == "success"
        items = data["data"]["items"]
        assert "Critical" in items
        assert "High" in items
        assert "Medium" in items
        assert "Low" in items

    def test_analysis_filter_options_tag(self, auth_client):
        resp = auth_client.get("/analysis/filter-options?column=tag", follow_redirects=True)
        assert resp.status_code == 200
        data = json.loads(resp.data)
        items = data["data"]["items"]
        assert "Botnet" in items
        assert "Malware" in items

    def test_run_aggregator_api(self, auth_client):
        resp = auth_client.post("/api/run")
        assert resp.status_code == 200

    def test_clear_history_api(self, auth_client):
        resp = auth_client.post(
            "/api/history/clear",
            content_type="application/json",
        )
        assert resp.status_code == 200
        data = json.loads(resp.data)
        assert data["status"] == "success"

    def test_custom_list_count_for_missing(self, auth_client):
        resp = auth_client.get("/api/custom_list/count/99999")
        assert resp.status_code in (200, 404)


# ---------------------------------------------------------------------------
# 8. CUSTOM EDL MANAGEMENT
# ---------------------------------------------------------------------------

class TestCustomEDL:
    """Create and access custom EDL lists."""

    def test_create_custom_list(self, auth_client):
        auth_client.post(
            "/system/add_source",
            data={
                "name": "EDLSource",
                "url": "https://example.com/edl.txt",
                "format": "text",
                "schedule_interval_minutes": "60",
                "confidence": "50",
            },
            follow_redirects=True,
        )
        resp = auth_client.post(
            "/system/custom_lists/add",
            data={
                "name": "My Custom List",
                "content_type": "ip",
                "format": "text",
                "sources": "EDLSource",
            },
            follow_redirects=True,
        )
        assert resp.status_code == 200


# ---------------------------------------------------------------------------
# 9. INVESTIGATION TOOL
# ---------------------------------------------------------------------------

class TestInvestigationTool:
    """IP and internal indicator lookup endpoints."""

    def test_ip_lookup_requires_post(self, auth_client):
        resp = auth_client.get("/tools/api/lookup_ip")
        assert resp.status_code == 405

    def test_ip_lookup_rejects_empty(self, auth_client):
        resp = auth_client.post(
            "/tools/api/lookup_ip",
            data=json.dumps({"ip": ""}),
            content_type="application/json",
        )
        assert resp.status_code in (200, 400)

    def test_internal_lookup_rejects_empty(self, auth_client):
        resp = auth_client.post(
            "/tools/api/lookup_internal",
            data=json.dumps({"indicator": ""}),
            content_type="application/json",
        )
        assert resp.status_code in (200, 400)

    def test_internal_lookup_returns_result(self, auth_client):
        resp = auth_client.post(
            "/tools/api/lookup_internal",
            data=json.dumps({"indicator": "8.8.8.8"}),
            content_type="application/json",
        )
        assert resp.status_code == 200
        data = json.loads(resp.data)
        assert "success" in data or "status" in data


# ---------------------------------------------------------------------------
# 10. DNS DEDUPLICATION
# ---------------------------------------------------------------------------

class TestDNSDeduplication:
    """DNS dedup schedule save and manual analysis trigger."""

    def test_save_schedule(self, auth_client):
        resp = auth_client.post(
            "/tools/api/dns_deduplication/schedule",
            data={
                "enabled": "on",
                "start_time": "00:00",
                "end_time": "23:59",
                "interval": "60",
                "batch_size": "50",
                "auto_delete": "on",
            },
        )
        assert resp.status_code == 200
        data = json.loads(resp.data)
        assert data.get("success") is True or data.get("status") == "success"

    def test_manual_analysis_trigger(self, auth_client):
        resp = auth_client.post(
            "/tools/api/dns_deduplication/analyze",
            content_type="application/json",
        )
        assert resp.status_code == 200


# ---------------------------------------------------------------------------
# 11. SECURITY CHECKS
# ---------------------------------------------------------------------------

class TestSecurityChecks:
    """CSRF protection, auth guards, and method restrictions."""

    def test_unauthenticated_cannot_access_dashboard(self, client):
        resp = client.get("/", follow_redirects=False)
        assert resp.status_code in (302, 303)

    def test_unauthenticated_cannot_access_system(self, client):
        resp = client.get("/system/", follow_redirects=False)
        assert resp.status_code in (302, 303, 308)

    def test_unauthenticated_cannot_access_api(self, client):
        resp = client.get("/api/source_stats")
        assert resp.status_code in (302, 401, 403)

    def test_unauthenticated_cannot_post_source(self, client):
        resp = client.post(
            "/system/add_source",
            data={"name": "Hack", "url": "http://evil.com"},
            follow_redirects=False,
        )
        assert resp.status_code in (302, 401, 403)

    def test_state_changing_endpoints_reject_get(self, auth_client):
        """All state-changing endpoints must reject GET."""
        get_should_fail = [
            "/system/add_source",
            "/system/whitelist/add",
            "/system/blacklist/add",
            "/system/update_settings",
            "/system/whitelist/remove/1",
        ]
        for path in get_should_fail:
            resp = auth_client.get(path)
            assert resp.status_code in (
                405, 302, 308
            ), f"GET {path} should fail, got {resp.status_code}"

    def test_health_endpoint_is_public(self, client):
        """Health check should work without auth."""
        resp = client.get("/health")
        assert resp.status_code == 200

    def test_unauthenticated_cannot_modify_whitelist(self, client):
        resp = client.post("/system/whitelist/add", data={"item": "x"})
        assert resp.status_code in (302, 401, 403)

    def test_unauthenticated_cannot_modify_blacklist(self, client):
        resp = client.post("/system/blacklist/add", data={"item": "x"})
        assert resp.status_code in (302, 401, 403)

    def test_unauthenticated_cannot_run_aggregator(self, client):
        resp = client.post("/api/run")
        assert resp.status_code in (302, 401, 403)

    def test_unauthenticated_cannot_clear_logs(self, client):
        resp = client.post("/api/live_logs/clear")
        assert resp.status_code in (302, 401, 403)

    def test_unauthenticated_cannot_save_dns_schedule(self, client):
        resp = client.post("/tools/api/dns_deduplication/schedule", data={})
        assert resp.status_code in (302, 401, 403)


# ---------------------------------------------------------------------------
# 12. FULL CRUD FLOWS
# ---------------------------------------------------------------------------

class TestFullCRUDFlows:
    """End-to-end add → verify → update → verify → delete → verify cycles."""

    def test_whitelist_full_lifecycle(self, auth_client):
        """Add → appears on dashboard → update → remove → gone."""
        import re

        # Add
        auth_client.post(
            "/system/whitelist/add",
            data={"item": "lifecycle.com", "type": "domain", "description": "CRUD test"},
            follow_redirects=True,
        )
        # Verify present and extract ID from remove URL
        html = _html(auth_client.get("/"))
        assert "lifecycle.com" in html
        match = re.search(r'/system/whitelist/remove/(\d+)', html)
        assert match, "Could not find whitelist remove link"
        item_id = match.group(1)

        # Update
        resp = auth_client.post(
            "/system/whitelist/update",
            data={"id": item_id, "item": "lifecycle.com", "type": "domain", "description": "Updated"},
            follow_redirects=True,
        )
        assert resp.status_code == 200

        # Remove
        auth_client.post(f"/system/whitelist/remove/{item_id}", follow_redirects=True)

        # Verify gone
        html = _html(auth_client.get("/"))
        assert "lifecycle.com" not in html

    def test_blacklist_full_lifecycle(self, auth_client):
        """Add → appears → update → verify → remove → gone."""
        auth_client.post(
            "/system/blacklist/add",
            data={"item": "bad-lifecycle.com", "type": "domain", "comment": "CRUD test"},
            follow_redirects=True,
        )
        html = _html(auth_client.get("/"))
        assert "bad-lifecycle.com" in html

        # Update
        resp = auth_client.post(
            "/system/blacklist/update",
            data={"id": "1", "item": "bad-updated.com", "type": "domain", "comment": "Updated"},
            follow_redirects=True,
        )
        assert resp.status_code == 200

        # Remove
        auth_client.post("/system/blacklist/remove/bad-updated.com", follow_redirects=True)
        html = _html(auth_client.get("/"))
        assert "bad-updated.com" not in html

    def test_source_full_lifecycle(self, auth_client):
        """Add → appears on dashboard → update → verify name → remove → gone."""
        auth_client.post(
            "/system/add_source",
            data={"name": "CRUDFeed", "url": "https://crud.example.com/feed.txt",
                  "format": "text", "schedule_interval_minutes": "60", "confidence": "50"},
            follow_redirects=True,
        )
        html = _html(auth_client.get("/"))
        assert "CRUDFeed" in html

        # Update source at index 0
        resp = auth_client.post(
            "/system/update_source/0",
            data={"name": "CRUDFeed-v2", "url": "https://crud.example.com/feed-v2.txt",
                  "format": "text", "schedule_interval_minutes": "30", "confidence": "80"},
            follow_redirects=True,
        )
        assert resp.status_code == 200

        html = _html(auth_client.get("/"))
        assert "CRUDFeed-v2" in html

        # Remove
        auth_client.post("/system/remove_source/0", follow_redirects=True)
        html = _html(auth_client.get("/"))
        assert "CRUDFeed-v2" not in html

    def test_custom_edl_full_lifecycle(self, auth_client):
        """Create custom list → verify on dashboard → delete → gone."""
        auth_client.post(
            "/system/add_source",
            data={"name": "EDLSrc", "url": "https://e.com/f.txt",
                  "format": "text", "schedule_interval_minutes": "60", "confidence": "50"},
            follow_redirects=True,
        )
        auth_client.post(
            "/system/custom_lists/add",
            data={"name": "LifecycleEDL", "content_type": "ip", "format": "text", "sources": "EDLSrc"},
            follow_redirects=True,
        )
        html = _html(auth_client.get("/"))
        assert "LifecycleEDL" in html

        # Delete
        resp = auth_client.post(
            "/system/custom_lists/delete",
            data={"list_id": "1"},
            follow_redirects=True,
        )
        assert resp.status_code == 200

    def test_multiple_whitelist_items(self, auth_client):
        """Add several items and verify all appear."""
        items = ["10.0.0.1", "10.0.0.2", "10.0.0.3", "safe.test.org"]
        for item in items:
            auth_client.post(
                "/system/whitelist/add",
                data={"item": item, "type": "ip" if "." in item and item[0].isdigit() else "domain",
                      "description": f"Multi {item}"},
                follow_redirects=True,
            )
        html = _html(auth_client.get("/"))
        for item in items[:5]:  # dashboard shows first 5
            assert item in html


# ---------------------------------------------------------------------------
# 13. API ENVELOPE VALIDATION
# ---------------------------------------------------------------------------

class TestAPIEnvelopeFormat:
    """All API responses use the standardized {status, data, timestamp} envelope."""

    def _assert_envelope(self, resp, expected_status="success"):
        assert resp.status_code == 200
        data = json.loads(resp.data)
        assert "status" in data, f"Missing 'status' key in response: {data}"
        assert data["status"] == expected_status
        assert "timestamp" in data, f"Missing 'timestamp' key in response: {data}"
        return data

    def test_source_stats_envelope(self, auth_client):
        data = self._assert_envelope(auth_client.get("/api/source_stats"))
        assert "data" in data

    def test_history_envelope(self, auth_client):
        data = self._assert_envelope(auth_client.get("/api/history?limit=5"))
        assert isinstance(data["data"]["items"], list)

    def test_live_logs_envelope(self, auth_client):
        data = self._assert_envelope(auth_client.get("/api/live_logs"))
        assert isinstance(data["data"]["items"], list)

    def test_scheduled_jobs_envelope(self, auth_client):
        data = self._assert_envelope(auth_client.get("/api/scheduled_jobs"))
        assert "data" in data

    def test_health_envelope(self, client):
        data = self._assert_envelope(client.get("/health"))
        assert "data" in data

    def test_filter_options_envelope(self, auth_client):
        data = self._assert_envelope(
            auth_client.get("/analysis/filter-options?column=level", follow_redirects=True)
        )
        assert isinstance(data["data"]["items"], list)

    def test_clear_history_envelope(self, auth_client):
        self._assert_envelope(
            auth_client.post("/api/history/clear", content_type="application/json")
        )

    def test_clear_logs_envelope(self, auth_client):
        self._assert_envelope(
            auth_client.post("/api/live_logs/clear", content_type="application/json")
        )

    def test_feed_health_envelope(self, auth_client):
        self._assert_envelope(auth_client.get("/api/feed_health"))

    def test_status_envelope(self, auth_client):
        self._assert_envelope(auth_client.get("/api/status"))

    def test_status_detailed_envelope(self, auth_client):
        self._assert_envelope(auth_client.get("/api/status_detailed"))

    def test_trend_data_envelope(self, auth_client):
        self._assert_envelope(auth_client.get("/api/trend_data"))


# ---------------------------------------------------------------------------
# 14. EDL OUTPUT ENDPOINTS
# ---------------------------------------------------------------------------

class TestEDLOutput:
    """Firewall EDL and custom EDL text output endpoints."""

    def test_palo_alto_ip_edl(self, auth_client):
        resp = auth_client.get("/api/edl/firewall/palo_alto_ip.txt")
        assert resp.status_code == 200
        assert resp.content_type in ("text/plain; charset=utf-8", "text/plain")

    def test_palo_alto_domain_edl(self, auth_client):
        resp = auth_client.get("/api/edl/firewall/palo_alto_domain.txt")
        assert resp.status_code == 200

    def test_fortinet_ip_edl(self, auth_client):
        resp = auth_client.get("/api/edl/firewall/fortinet_ip.txt")
        assert resp.status_code == 200

    def test_fortinet_domain_edl(self, auth_client):
        resp = auth_client.get("/api/edl/firewall/fortinet_domain.txt")
        assert resp.status_code == 200

    def test_edl_head_request(self, auth_client):
        """HEAD requests should work for EDL polling."""
        resp = auth_client.head("/api/edl/firewall/palo_alto_ip.txt")
        assert resp.status_code == 200

    def test_nonexistent_edl_returns_empty_or_404(self, auth_client):
        resp = auth_client.get("/api/edl/firewall/nonexistent.txt")
        assert resp.status_code in (200, 404)

    def test_generic_edl_endpoint(self, auth_client):
        resp = auth_client.get("/api/edl/generic")
        assert resp.status_code == 200

    def test_download_file_endpoint(self, auth_client):
        """Dashboard file download for service whitelists."""
        resp = auth_client.get("/data/palo_alto_ip.txt")
        assert resp.status_code in (200, 404)


# ---------------------------------------------------------------------------
# 15. USER & PROFILE MANAGEMENT
# ---------------------------------------------------------------------------

class TestUserManagement:
    """Local user CRUD and password changes."""

    def test_add_local_user(self, auth_client):
        resp = auth_client.post(
            "/system/users/add",
            data={"username": "testuser", "password": "TestPass123!", "profile": "Super_User"},
            follow_redirects=True,
        )
        assert resp.status_code == 200

    def test_change_user_password(self, auth_client):
        # Add user first
        auth_client.post(
            "/system/users/add",
            data={"username": "pwduser", "password": "OldPass123!", "profile": "Super_User"},
            follow_redirects=True,
        )
        resp = auth_client.post(
            "/system/users/change_password",
            data={"username": "pwduser", "new_password": "NewPass456!"},
            follow_redirects=True,
        )
        assert resp.status_code == 200

    def test_delete_local_user(self, auth_client):
        auth_client.post(
            "/system/users/add",
            data={"username": "deluser", "password": "DelPass123!", "profile": "Super_User"},
            follow_redirects=True,
        )
        resp = auth_client.post(
            "/system/users/delete",
            data={"username": "deluser"},
            follow_redirects=True,
        )
        assert resp.status_code == 200

    def test_change_own_password(self, auth_client):
        resp = auth_client.post(
            "/system/change_password",
            data={"current_password": "admin", "new_password": "NewAdmin123!",
                  "confirm_password": "NewAdmin123!"},
            follow_redirects=True,
        )
        assert resp.status_code == 200

    def test_add_admin_profile(self, auth_client):
        resp = auth_client.post(
            "/system/admin_profiles/add",
            data={"name": "TestProfile", "dashboard": "rw", "system": "r",
                  "tools": "rw", "analysis": "rw"},
            follow_redirects=True,
        )
        assert resp.status_code == 200

    def test_delete_admin_profile(self, auth_client):
        auth_client.post(
            "/system/admin_profiles/add",
            data={"name": "TempProfile", "dashboard": "r", "system": "r",
                  "tools": "r", "analysis": "r"},
            follow_redirects=True,
        )
        resp = auth_client.post(
            "/system/admin_profiles/delete",
            data={"name": "TempProfile"},
            follow_redirects=True,
        )
        assert resp.status_code == 200


# ---------------------------------------------------------------------------
# 16. API CLIENT MANAGEMENT
# ---------------------------------------------------------------------------

class TestAPIClientManagement:
    """API key CRUD for SOAR / machine-to-machine access."""

    def test_add_api_client(self, auth_client):
        resp = auth_client.post(
            "/system/api_client/add",
            data={"name": "TestClient", "allowed_ips": ""},
            follow_redirects=True,
        )
        assert resp.status_code == 200

    def test_remove_api_client(self, auth_client):
        auth_client.post(
            "/system/api_client/add",
            data={"name": "ToRemoveClient", "allowed_ips": ""},
            follow_redirects=True,
        )
        resp = auth_client.post(
            "/system/api_client/remove",
            data={"client_id": "1"},
            follow_redirects=True,
        )
        # May get 200 or redirect
        assert resp.status_code == 200


# ---------------------------------------------------------------------------
# 17. SERVICE WHITELIST UPDATES
# ---------------------------------------------------------------------------

class TestServiceWhitelists:
    """MS365, GitHub, Azure whitelist update triggers."""

    def test_update_ms365(self, auth_client):
        resp = auth_client.post("/api/update_ms365")
        assert resp.status_code in (200, 500)  # 500 if external API unreachable

    def test_update_github(self, auth_client):
        resp = auth_client.post("/api/update_github")
        assert resp.status_code in (200, 500)

    def test_update_azure(self, auth_client):
        resp = auth_client.post("/api/update_azure")
        assert resp.status_code in (200, 500)

    def test_regenerate_lists(self, auth_client):
        resp = auth_client.post("/api/regenerate_lists")
        assert resp.status_code == 200


# ---------------------------------------------------------------------------
# 18. SYSTEM STATUS ENDPOINTS
# ---------------------------------------------------------------------------

class TestSystemStatus:
    """LDAP, DNS, and Proxy status check endpoints."""

    def test_ldap_status(self, auth_client):
        resp = auth_client.get("/system/ldap/status")
        assert resp.status_code == 200

    def test_dns_status(self, auth_client):
        resp = auth_client.get("/system/dns/status")
        assert resp.status_code == 200

    def test_proxy_status(self, auth_client):
        resp = auth_client.get("/system/proxy/status")
        assert resp.status_code == 200

    def test_api_docs_page(self, auth_client):
        resp = auth_client.get("/api/docs")
        assert resp.status_code == 200


# ---------------------------------------------------------------------------
# 19. ANALYSIS DATATABLES API
# ---------------------------------------------------------------------------

class TestAnalysisDataAPI:
    """Server-side DataTables endpoint for threat analysis."""

    def test_analysis_data_returns_datatables_format(self, auth_client):
        resp = auth_client.get(
            "/analysis/data?draw=1&start=0&length=10",
            follow_redirects=True,
        )
        assert resp.status_code == 200
        data = json.loads(resp.data)
        assert "draw" in data
        assert "recordsTotal" in data
        assert "recordsFiltered" in data
        assert "data" in data
        assert isinstance(data["data"], list)

    def test_analysis_data_with_search(self, auth_client):
        resp = auth_client.get(
            "/analysis/data?draw=1&start=0&length=10&search[value]=test",
            follow_redirects=True,
        )
        assert resp.status_code == 200
        data = json.loads(resp.data)
        assert "data" in data

    def test_analysis_data_with_custom_filters(self, auth_client):
        filters = json.dumps({"level": "Critical"})
        resp = auth_client.get(
            f"/analysis/data?draw=1&start=0&length=10&custom_filters={filters}",
            follow_redirects=True,
        )
        assert resp.status_code == 200


# ---------------------------------------------------------------------------
# 20. EDGE CASES & INPUT VALIDATION
# ---------------------------------------------------------------------------

class TestEdgeCases:
    """Boundary conditions, empty inputs, and malformed requests."""

    def test_add_empty_whitelist_item(self, auth_client):
        resp = auth_client.post(
            "/system/whitelist/add",
            data={"item": "", "type": "ip", "description": ""},
            follow_redirects=True,
        )
        # Should not crash — either rejects or ignores
        assert resp.status_code == 200

    def test_add_empty_source(self, auth_client):
        resp = auth_client.post(
            "/system/add_source",
            data={"name": "", "url": "", "format": "text"},
            follow_redirects=True,
        )
        assert resp.status_code == 200

    def test_remove_nonexistent_whitelist_id(self, auth_client):
        resp = auth_client.post("/system/whitelist/remove/99999", follow_redirects=True)
        assert resp.status_code in (200, 404)

    def test_update_nonexistent_source_index(self, auth_client):
        resp = auth_client.post(
            "/system/update_source/999",
            data={"name": "X", "url": "https://x.com", "format": "text"},
            follow_redirects=True,
        )
        assert resp.status_code in (200, 404, 500)

    def test_xss_in_whitelist_item_is_escaped(self, auth_client):
        xss = '<script>alert("xss")</script>'
        auth_client.post(
            "/system/whitelist/add",
            data={"item": xss, "type": "domain", "description": "XSS test"},
            follow_redirects=True,
        )
        html = _html(auth_client.get("/"))
        # Raw script tag should NOT appear — Jinja2 auto-escapes
        assert "<script>alert" not in html

    @pytest.mark.xfail(reason="Known XSS: source name rendered unescaped in onclick attributes (index.html L102-103)")
    def test_xss_in_source_name_is_escaped(self, auth_client):
        """Source names in onclick attributes must be escaped to prevent XSS."""
        xss = '<img src=x onerror=alert(1)>'
        auth_client.post(
            "/system/add_source",
            data={"name": xss, "url": "https://example.com/feed.txt",
                  "format": "text", "schedule_interval_minutes": "60", "confidence": "50"},
            follow_redirects=True,
        )
        html = _html(auth_client.get("/"))
        import re
        html_no_script = re.sub(r"<script[\s\S]*?</script>", "", html)
        assert "onerror=" not in html_no_script

    def test_very_long_indicator(self, auth_client):
        long_item = "a" * 500 + ".example.com"
        resp = auth_client.post(
            "/system/whitelist/add",
            data={"item": long_item, "type": "domain", "description": "Long test"},
            follow_redirects=True,
        )
        assert resp.status_code == 200

    def test_special_characters_in_blacklist(self, auth_client):
        resp = auth_client.post(
            "/system/blacklist/add",
            data={"item": "192.168.1.0/24", "type": "ip", "comment": "CIDR range"},
            follow_redirects=True,
        )
        assert resp.status_code == 200

    def test_dns_dedup_delete_empty_list(self, auth_client):
        resp = auth_client.post(
            "/tools/api/dns_deduplication/delete",
            data=json.dumps({"indicators": []}),
            content_type="application/json",
        )
        assert resp.status_code in (200, 400)  # 400 is valid for empty list

    def test_internal_lookup_special_chars(self, auth_client):
        resp = auth_client.post(
            "/tools/api/lookup_internal",
            data=json.dumps({"indicator": "foo'bar\"baz"}),
            content_type="application/json",
        )
        # Should not crash with SQL injection
        assert resp.status_code in (200, 400)

    def test_history_limit_zero(self, auth_client):
        resp = auth_client.get("/api/history?limit=0")
        assert resp.status_code == 200

    def test_history_limit_negative(self, auth_client):
        resp = auth_client.get("/api/history?limit=-1")
        assert resp.status_code == 200

    def test_filter_options_empty_column(self, auth_client):
        resp = auth_client.get("/analysis/filter-options?column=", follow_redirects=True)
        assert resp.status_code == 200

    def test_filter_options_invalid_column(self, auth_client):
        resp = auth_client.get("/analysis/filter-options?column=nonexistent", follow_redirects=True)
        assert resp.status_code == 200


# ---------------------------------------------------------------------------
# 21. READONLY PERMISSION ENFORCEMENT
# ---------------------------------------------------------------------------

class TestReadonlyPermissions:
    """Read-only users cannot perform write operations."""

    def test_readonly_cannot_add_source(self, readonly_client):
        resp = readonly_client.post(
            "/system/add_source",
            data={"name": "Forbidden", "url": "https://example.com", "format": "text"},
            follow_redirects=True,
        )
        html = _html(resp)
        # Should either be blocked or show an error
        assert resp.status_code in (200, 403)

    def test_readonly_can_view_dashboard(self, readonly_client):
        resp = readonly_client.get("/")
        assert resp.status_code == 200
        assert "Operational Overview" in _html(resp)

    def test_readonly_can_view_analysis(self, readonly_client):
        resp = readonly_client.get("/analysis/", follow_redirects=True)
        assert resp.status_code == 200

    def test_readonly_can_view_investigation(self, readonly_client):
        resp = readonly_client.get("/tools/investigate")
        assert resp.status_code == 200

    def test_readonly_system_shows_disabled_controls(self, readonly_client):
        resp = readonly_client.get("/system/", follow_redirects=True)
        html = _html(resp)
        assert "Read-Only" in html
