"""
tests/test_v24_features.py
Unit tests for v2.4.0 new features:
  - list_management_required decorator
  - GET /api/blacklist ?exclude_deceptor / ?only_deceptor filtering
  - POST /system/blacklist/clear_deceptor endpoint
  - lists permission module in admin profiles
"""
import json
import pytest


# ---------------------------------------------------------------------------
# Helper
# ---------------------------------------------------------------------------

def _seed_blacklist(app, items, clear=False):
    """Insert blacklist items directly into the test DB.

    Args:
        app: Flask app fixture (provides app context)
        items: list of (ip_value, comment) tuples
        clear: if True, delete all existing blacklist rows before inserting
    """
    from threat_feed_aggregator.db_manager import add_api_blacklist_item
    from threat_feed_aggregator.database.connection import db_transaction

    with app.app_context():
        if clear:
            with db_transaction() as db:
                db.execute("DELETE FROM api_blacklist")
        for value, comment in items:
            add_api_blacklist_item(value, item_type="ip", comment=comment)


def _location(response):
    """Return the Location header value for redirect assertions."""
    return response.headers.get("Location", "")


# ---------------------------------------------------------------------------
# A. TestListManagementRequired
# ---------------------------------------------------------------------------

class TestListManagementRequired:
    """Verify that list_management_required allows system:rw OR lists:rw
    and denies everyone else."""

    # ---- system:rw (auth_client) should be allowed -----------------------

    def test_system_rw_can_add_whitelist(self, auth_client):
        resp = auth_client.post(
            "/system/whitelist/add",
            data={"item": "10.0.0.1", "type": "ip", "description": "test"},
        )
        # Successful add → redirect back to dashboard (not login)
        assert resp.status_code == 302
        assert "login" not in _location(resp).lower()

    def test_system_rw_can_add_blacklist(self, auth_client):
        resp = auth_client.post(
            "/system/blacklist/add",
            data={"item": "8.8.8.8", "type": "ip", "comment": "test"},
        )
        assert resp.status_code == 302
        assert "login" not in _location(resp).lower()

    def test_system_rw_can_clear_deceptor(self, auth_client):
        resp = auth_client.post("/system/blacklist/clear_deceptor")
        assert resp.status_code == 200

    # ---- lists:rw only (lists_client) should be allowed ------------------

    def test_lists_rw_can_add_whitelist(self, lists_client):
        resp = lists_client.post(
            "/system/whitelist/add",
            data={"item": "10.0.0.2", "type": "ip", "description": "test"},
        )
        assert resp.status_code == 302
        assert "login" not in _location(resp).lower()

    def test_lists_rw_can_add_blacklist(self, lists_client):
        resp = lists_client.post(
            "/system/blacklist/add",
            data={"item": "1.2.3.4", "type": "ip", "comment": "test"},
        )
        assert resp.status_code == 302
        assert "login" not in _location(resp).lower()

    def test_lists_rw_can_clear_deceptor(self, lists_client):
        resp = lists_client.post("/system/blacklist/clear_deceptor")
        assert resp.status_code == 200

    # ---- read-only user (system:r, no lists) should be denied ------------

    def test_readonly_denied_whitelist_add(self, readonly_client):
        resp = readonly_client.post(
            "/system/whitelist/add",
            data={"item": "10.0.0.3", "type": "ip", "description": "test"},
        )
        assert resp.status_code == 302
        loc = _location(resp)
        assert "login" not in loc.lower()
        assert "dashboard" in loc.lower() or loc == "/" or loc.endswith("/")

    def test_readonly_denied_blacklist_add(self, readonly_client):
        resp = readonly_client.post(
            "/system/blacklist/add",
            data={"item": "5.5.5.5", "type": "ip", "comment": "test"},
        )
        assert resp.status_code == 302
        assert "login" not in _location(resp).lower()

    def test_readonly_denied_clear_deceptor(self, readonly_client):
        resp = readonly_client.post("/system/blacklist/clear_deceptor")
        assert resp.status_code == 302
        assert "login" not in _location(resp).lower()

    # ---- unauthenticated → login redirect --------------------------------

    def test_anonymous_redirected_whitelist_add(self, client):
        resp = client.post(
            "/system/whitelist/add",
            data={"item": "10.0.0.4", "type": "ip"},
        )
        assert resp.status_code == 302
        assert "login" in _location(resp).lower()

    def test_anonymous_redirected_blacklist_add(self, client):
        resp = client.post(
            "/system/blacklist/add",
            data={"item": "9.9.9.9", "type": "ip"},
        )
        assert resp.status_code == 302
        assert "login" in _location(resp).lower()

    def test_anonymous_redirected_clear_deceptor(self, client):
        resp = client.post("/system/blacklist/clear_deceptor")
        assert resp.status_code == 302
        assert "login" in _location(resp).lower()


# ---------------------------------------------------------------------------
# B. TestBlacklistApiFiltering
# ---------------------------------------------------------------------------

class TestBlacklistApiFiltering:
    """Verify GET /api/blacklist?exclude_deceptor and ?only_deceptor params."""

    MISP_IP = "203.0.113.1"
    MISP_COMMENT = "MISP_BLOCK"
    DC_IP = "198.51.100.1"
    DC_COMMENT = "[FortiDeceptor] honeypot"

    def _seed(self, app):
        _seed_blacklist(app, [
            (self.MISP_IP, self.MISP_COMMENT),
            (self.DC_IP, self.DC_COMMENT),
        ], clear=True)

    # ---- response envelope -----------------------------------------------

    def test_response_envelope(self, app, auth_client):
        self._seed(app)
        resp = auth_client.get("/api/blacklist?per_page=100")
        assert resp.status_code == 200
        data = resp.json
        assert data["status"] == "success"
        assert "timestamp" in data
        assert "items" in data["data"]
        assert "total" in data["data"]

    # ---- no filter: all items returned ------------------------------------

    def test_no_filter_returns_all(self, app, auth_client):
        self._seed(app)
        resp = auth_client.get("/api/blacklist?per_page=100")
        items = resp.json["data"]["items"]
        ips = [i["item"] for i in items]
        assert self.MISP_IP in ips
        assert self.DC_IP in ips

    # ---- exclude_deceptor=true -------------------------------------------

    def test_exclude_deceptor_removes_fortideceptor_items(self, app, auth_client):
        self._seed(app)
        resp = auth_client.get("/api/blacklist?exclude_deceptor=true&per_page=100")
        assert resp.status_code == 200
        items = resp.json["data"]["items"]
        for item in items:
            assert "FortiDeceptor" not in (item.get("comment") or "")

    def test_exclude_deceptor_keeps_non_deceptor_items(self, app, auth_client):
        self._seed(app)
        resp = auth_client.get("/api/blacklist?exclude_deceptor=true&per_page=100")
        ips = [i["item"] for i in resp.json["data"]["items"]]
        assert self.MISP_IP in ips

    def test_exclude_deceptor_correct_total(self, app, auth_client):
        self._seed(app)
        resp = auth_client.get("/api/blacklist?exclude_deceptor=true&per_page=100")
        data = resp.json["data"]
        # Only the MISP item should pass the filter
        assert data["total"] == 1
        assert len(data["items"]) == 1

    def test_exclude_deceptor_empty_when_only_deceptor_exists(self, app, auth_client):
        _seed_blacklist(app, [(self.DC_IP, self.DC_COMMENT)], clear=True)
        resp = auth_client.get("/api/blacklist?exclude_deceptor=true&per_page=100")
        data = resp.json["data"]
        assert data["total"] == 0
        assert data["items"] == []

    # ---- only_deceptor=true ----------------------------------------------

    def test_only_deceptor_returns_fortideceptor_items(self, app, auth_client):
        self._seed(app)
        resp = auth_client.get("/api/blacklist?only_deceptor=true&per_page=100")
        assert resp.status_code == 200
        items = resp.json["data"]["items"]
        for item in items:
            assert "FortiDeceptor" in (item.get("comment") or "")

    def test_only_deceptor_excludes_non_deceptor(self, app, auth_client):
        self._seed(app)
        resp = auth_client.get("/api/blacklist?only_deceptor=true&per_page=100")
        ips = [i["item"] for i in resp.json["data"]["items"]]
        assert self.MISP_IP not in ips
        assert self.DC_IP in ips

    def test_only_deceptor_correct_total(self, app, auth_client):
        self._seed(app)
        resp = auth_client.get("/api/blacklist?only_deceptor=true&per_page=100")
        data = resp.json["data"]
        assert data["total"] == 1
        assert len(data["items"]) == 1

    def test_only_deceptor_empty_when_no_deceptor_exists(self, app, auth_client):
        _seed_blacklist(app, [(self.MISP_IP, self.MISP_COMMENT)], clear=True)
        resp = auth_client.get("/api/blacklist?only_deceptor=true&per_page=100")
        data = resp.json["data"]
        assert data["total"] == 0
        assert data["items"] == []

    # ---- pagination with filter ------------------------------------------

    def test_exclude_deceptor_pagination_correct(self, app, auth_client):
        """With per_page=1 and 1 non-deceptor item, page 1 has the item."""
        self._seed(app)
        resp = auth_client.get("/api/blacklist?exclude_deceptor=true&page=1&per_page=1")
        data = resp.json["data"]
        assert data["total"] == 1
        assert len(data["items"]) == 1
        assert data["items"][0]["item"] == self.MISP_IP

    # ---- authentication required -----------------------------------------

    def test_unauthenticated_blocked(self, client):
        resp = client.get("/api/blacklist?exclude_deceptor=true")
        assert resp.status_code == 302
        assert "login" in _location(resp).lower()


# ---------------------------------------------------------------------------
# C. TestClearDeceptorBlocks
# ---------------------------------------------------------------------------

class TestClearDeceptorBlocks:
    """Verify POST /system/blacklist/clear_deceptor endpoint."""

    MISP_IP = "203.0.113.10"
    DC_IP1 = "198.51.100.10"
    DC_IP2 = "198.51.100.11"
    DC_COMMENT = "[FortiDeceptor] auto-block"

    def _seed_mixed(self, app):
        _seed_blacklist(app, [
            (self.MISP_IP, "MISP_BLOCK"),
            (self.DC_IP1, self.DC_COMMENT),
            (self.DC_IP2, self.DC_COMMENT),
        ], clear=True)

    # ---- success scenarios -----------------------------------------------

    def test_clear_returns_json_success(self, auth_client):
        resp = auth_client.post("/system/blacklist/clear_deceptor")
        assert resp.status_code == 200
        data = resp.json
        assert data["status"] == "success"
        assert "message" in data

    def test_clear_reports_correct_count(self, app, auth_client):
        self._seed_mixed(app)
        resp = auth_client.post("/system/blacklist/clear_deceptor")
        assert resp.status_code == 200
        data = resp.json
        assert "2" in data["message"]

    def test_clear_removes_only_deceptor_items(self, app, auth_client):
        self._seed_mixed(app)
        auth_client.post("/system/blacklist/clear_deceptor")

        # FortiDeceptor items should be gone
        bl_resp = auth_client.get("/api/blacklist?per_page=100")
        items = bl_resp.json["data"]["items"]
        ips = [i["item"] for i in items]
        assert self.DC_IP1 not in ips
        assert self.DC_IP2 not in ips

    def test_clear_keeps_non_deceptor_items(self, app, auth_client):
        self._seed_mixed(app)
        auth_client.post("/system/blacklist/clear_deceptor")

        bl_resp = auth_client.get("/api/blacklist?per_page=100")
        items = bl_resp.json["data"]["items"]
        ips = [i["item"] for i in items]
        assert self.MISP_IP in ips

    def test_clear_zero_count_when_no_deceptor(self, app, auth_client):
        _seed_blacklist(app, [(self.MISP_IP, "MISP_BLOCK")], clear=True)
        resp = auth_client.post("/system/blacklist/clear_deceptor")
        assert resp.status_code == 200
        assert "0" in resp.json["message"]

    def test_clear_empty_db_returns_zero(self, auth_client):
        resp = auth_client.post("/system/blacklist/clear_deceptor")
        assert resp.status_code == 200
        assert "0" in resp.json["message"]

    # ---- permission checks -----------------------------------------------

    def test_lists_rw_can_clear(self, app, lists_client):
        self._seed_mixed(app)
        resp = lists_client.post("/system/blacklist/clear_deceptor")
        assert resp.status_code == 200
        assert resp.json["status"] == "success"

    def test_readonly_denied(self, readonly_client):
        resp = readonly_client.post("/system/blacklist/clear_deceptor")
        assert resp.status_code == 302
        assert "login" not in _location(resp).lower()

    def test_anonymous_denied(self, client):
        resp = client.post("/system/blacklist/clear_deceptor")
        assert resp.status_code == 302
        assert "login" in _location(resp).lower()


# ---------------------------------------------------------------------------
# D. TestListsPermissionInProfiles
# ---------------------------------------------------------------------------

class TestListsPermissionInProfiles:
    """Verify that admin profiles can store and retrieve the 'lists' permission."""

    def test_add_profile_with_lists_permission(self, auth_client):
        perms = json.dumps({
            "dashboard": "rw",
            "system": "r",
            "tools": "r",
            "lists": "rw",
        })
        resp = auth_client.post(
            "/system/admin_profiles/add",
            data={
                "name": "ListManagerProfile",
                "description": "Can manage lists only",
                "permissions": perms,
            },
        )
        # Should redirect to system page (success)
        assert resp.status_code == 302
        assert "login" not in _location(resp).lower()

    def test_lists_permission_preserved_in_db(self, app, auth_client):
        perms = json.dumps({
            "dashboard": "rw",
            "system": "r",
            "tools": "r",
            "lists": "rw",
        })
        auth_client.post(
            "/system/admin_profiles/add",
            data={
                "name": "ListManagerProfile2",
                "description": "Test profile",
                "permissions": perms,
            },
        )
        # Read profiles back from DB
        from threat_feed_aggregator.db_manager import get_admin_profiles
        with app.app_context():
            profiles = get_admin_profiles()

        match = next(
            (p for p in profiles if p["name"] == "ListManagerProfile2"), None
        )
        assert match is not None
        saved_perms = json.loads(match["permissions"])
        assert saved_perms.get("lists") == "rw"

    def test_default_superuser_has_lists_rw_in_new_install(self, app):
        """Fresh install: Super_User profile should have lists:rw."""
        from threat_feed_aggregator.db_manager import get_admin_profiles
        with app.app_context():
            profiles = get_admin_profiles()

        su = next((p for p in profiles if p["name"] == "Super_User"), None)
        if su:
            saved_perms = json.loads(su["permissions"])
            assert saved_perms.get("lists") == "rw"
