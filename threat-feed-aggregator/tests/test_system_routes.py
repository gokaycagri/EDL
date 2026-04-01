"""
System route tests — user management, source management, settings, import/export.

Covers the major gaps in system.py route testing.
"""

import io
import json

import pytest
from unittest.mock import patch, MagicMock


# ============================================================
# User Management
# ============================================================

class TestUserAdd:
    """POST /system/users/add"""

    def test_requires_auth(self, client):
        resp = client.post("/system/users/add", data={
            "username": "newuser", "password": "Strong1Pass", "profile_id": 1,
        })
        assert resp.status_code == 302
        assert "/auth/login" in resp.headers.get("Location", "")

    def test_missing_fields_flash_error(self, auth_client):
        resp = auth_client.post("/system/users/add", data={}, follow_redirects=True)
        assert b"required" in resp.data.lower()

    def test_weak_password_rejected(self, auth_client):
        resp = auth_client.post("/system/users/add", data={
            "username": "testuser", "password": "short", "profile_id": 1,
        }, follow_redirects=True)
        assert b"at least" in resp.data

    @patch("threat_feed_aggregator.routes.system.add_local_user", return_value=(True, "Created"))
    @patch("threat_feed_aggregator.services.audit_service.log_action")
    def test_valid_user_created(self, mock_audit, mock_add, auth_client):
        resp = auth_client.post("/system/users/add", data={
            "username": "newadmin", "password": "SecureP@ss1", "profile_id": 1,
        }, follow_redirects=True)
        assert mock_add.called
        assert b"added successfully" in resp.data


class TestUserDelete:
    """POST /system/users/delete"""

    def test_requires_auth(self, client):
        resp = client.post("/system/users/delete", data={"username": "test"})
        assert resp.status_code == 302

    @patch("threat_feed_aggregator.routes.system.delete_local_user", return_value=(True, "Deleted"))
    def test_delete_success(self, mock_del, auth_client):
        resp = auth_client.post("/system/users/delete", data={"username": "testuser"}, follow_redirects=True)
        assert mock_del.called
        assert b"deleted successfully" in resp.data

    @patch("threat_feed_aggregator.routes.system.delete_local_user", return_value=(False, "Not found"))
    def test_delete_failure(self, mock_del, auth_client):
        resp = auth_client.post("/system/users/delete", data={"username": "ghost"}, follow_redirects=True)
        assert b"Error" in resp.data


# ============================================================
# Source Management
# ============================================================

class TestSourceAdd:
    """POST /system/add_source"""

    def test_requires_auth(self, client):
        resp = client.post("/system/add_source", data={"name": "test", "url": "http://test"})
        assert resp.status_code == 302

    @patch("threat_feed_aggregator.routes.system.write_config")
    @patch("threat_feed_aggregator.routes.system.read_config", return_value={"source_urls": []})
    @patch("threat_feed_aggregator.app.update_scheduled_jobs", create=True)
    def test_add_new_source(self, mock_sched, mock_read, mock_write, auth_client):
        resp = auth_client.post("/system/add_source", data={
            "name": "TestFeed",
            "url": "https://example.com/feed.txt",
            "format": "text",
            "confidence": 50,
        })
        assert resp.status_code == 302
        assert mock_write.called
        config_written = mock_write.call_args[0][0]
        assert len(config_written["source_urls"]) == 1
        assert config_written["source_urls"][0]["name"] == "TestFeed"

    @patch("threat_feed_aggregator.routes.system.write_config")
    @patch("threat_feed_aggregator.routes.system.read_config", return_value={
        "source_urls": [{"name": "Existing", "url": "https://example.com/feed.txt"}]
    })
    @patch("threat_feed_aggregator.app.update_scheduled_jobs", create=True)
    def test_duplicate_url_rejected(self, mock_sched, mock_read, mock_write, auth_client):
        resp = auth_client.post("/system/add_source", data={
            "name": "DupeFeed",
            "url": "https://example.com/feed.txt",
            "format": "text",
        }, follow_redirects=True)
        assert not mock_write.called
        assert b"already configured" in resp.data


class TestSourceRemove:
    """POST /system/remove_source/<int:index>"""

    def test_rejects_get(self, auth_client):
        resp = auth_client.get("/system/remove_source/0")
        assert resp.status_code == 405

    @patch("threat_feed_aggregator.routes.system.write_config")
    @patch("threat_feed_aggregator.routes.system.read_config", return_value={
        "source_urls": [{"name": "ToDelete", "url": "http://delete.me"}]
    })
    @patch("threat_feed_aggregator.app.update_scheduled_jobs", create=True)
    def test_remove_valid_index(self, mock_sched, mock_read, mock_write, auth_client):
        resp = auth_client.post("/system/remove_source/0")
        assert resp.status_code == 302
        assert mock_write.called
        assert len(mock_write.call_args[0][0]["source_urls"]) == 0


# ============================================================
# Whitelist / Blacklist Operations
# ============================================================

class TestWhitelistAdd:
    """POST /system/whitelist/add"""

    @patch("threat_feed_aggregator.routes.system.add_whitelist_item", return_value=(True, "Added"))
    @patch("threat_feed_aggregator.routes.system.delete_whitelisted_indicators")
    def test_valid_ip_added(self, mock_delete, mock_add, auth_client):
        resp = auth_client.post("/system/whitelist/add", data={
            "item": "10.0.0.1", "type": "ip", "description": "Test",
        }, follow_redirects=True)
        assert mock_add.called
        assert b"added to safe list" in resp.data

    def test_invalid_item_rejected(self, auth_client):
        resp = auth_client.post("/system/whitelist/add", data={
            "item": "not_valid!!!", "type": "ip",
        }, follow_redirects=True)
        assert b"not a valid" in resp.data


class TestBlacklistAdd:
    """POST /system/blacklist/add"""

    @patch("threat_feed_aggregator.aggregator.regenerate_edl_files")
    @patch("threat_feed_aggregator.routes.system.add_api_blacklist_item", return_value=(True, "Added"))
    def test_valid_ip_added(self, mock_add, mock_regen, auth_client):
        resp = auth_client.post("/system/blacklist/add", data={
            "item": "192.168.1.1", "type": "ip", "comment": "Test block",
        }, follow_redirects=True)
        assert mock_add.called
        assert b"added to block list" in resp.data

    def test_invalid_item_rejected(self, auth_client):
        resp = auth_client.post("/system/blacklist/add", data={
            "item": "not_valid!!!", "type": "ip",
        }, follow_redirects=True)
        assert b"not a valid" in resp.data


class TestBulkIndicatorDelete:
    """POST /system/indicators/bulk_delete"""

    def test_requires_auth(self, client):
        resp = client.post("/system/indicators/bulk_delete", data={"items": "1.1.1.1"})
        assert resp.status_code == 302
        assert "/auth/login" in resp.headers.get("Location", "")

    def test_requires_rw_permission(self, readonly_client):
        resp = readonly_client.post(
            "/system/indicators/bulk_delete",
            data={"items": "1.1.1.1"},
            follow_redirects=True,
        )
        assert b"Access Denied" in resp.data

    def test_empty_input_rejected(self, auth_client):
        resp = auth_client.post(
            "/system/indicators/bulk_delete",
            data={"items": ""},
            follow_redirects=True,
        )
        assert b"No indicators provided" in resp.data

    def test_invalid_only_input_rejected(self, auth_client):
        resp = auth_client.post(
            "/system/indicators/bulk_delete",
            data={"items": "not_valid!!!"},
            follow_redirects=True,
        )
        assert b"No valid indicators found" in resp.data

    @patch("threat_feed_aggregator.aggregator.regenerate_edl_files")
    @patch("threat_feed_aggregator.routes.system.delete_indicators", return_value=2)
    def test_bulk_delete_success(self, mock_delete, mock_regen, auth_client):
        resp = auth_client.post(
            "/system/indicators/bulk_delete",
            data={"items": "1.1.1.1\n8.8.8.8"},
            follow_redirects=True,
        )
        assert mock_delete.called
        assert mock_delete.call_args[0][0] == ["1.1.1.1", "8.8.8.8"]
        assert mock_regen.called
        assert b"Deleted 2 indicators from database" in resp.data

    @patch("threat_feed_aggregator.aggregator.regenerate_edl_files")
    @patch("threat_feed_aggregator.routes.system.remove_api_blacklist_item", return_value=True)
    @patch(
        "threat_feed_aggregator.routes.system.get_api_blacklist_item_by_value",
        side_effect=[{"id": 1}, None],
    )
    @patch("threat_feed_aggregator.routes.system.delete_indicators", return_value=1)
    def test_bulk_delete_with_blocklist_cleanup(self, mock_delete, mock_lookup, mock_remove, mock_regen, auth_client):
        resp = auth_client.post(
            "/system/indicators/bulk_delete",
            data={"items": "1.1.1.1\n8.8.8.8", "remove_from_blocklist": "on"},
            follow_redirects=True,
        )
        assert mock_delete.called
        assert mock_lookup.call_count == 2
        mock_remove.assert_called_once_with("1.1.1.1")
        assert mock_regen.called
        assert b"removed 1 from block list" in resp.data


# ============================================================
# Import / Export
# ============================================================

class TestWhitelistImport:
    """POST /system/whitelist/import"""

    def test_requires_file(self, auth_client):
        resp = auth_client.post("/system/whitelist/import", follow_redirects=True)
        assert b"No file part" in resp.data

    @patch("threat_feed_aggregator.routes.system.add_whitelist_item", return_value=(True, "Added"))
    @patch("threat_feed_aggregator.routes.system.delete_whitelisted_indicators")
    def test_import_text_file(self, mock_del, mock_add, auth_client):
        content = b"1.1.1.1\n2.2.2.2\n# comment\ninvalid!!!\n"
        data = {"import_file": (io.BytesIO(content), "safe_list.txt")}
        resp = auth_client.post(
            "/system/whitelist/import",
            data=data,
            content_type="multipart/form-data",
            follow_redirects=True,
        )
        # 2 valid IPs should be added (invalid!!! skipped)
        assert mock_add.call_count == 2
        # Only successfully added items should be in delete call
        assert mock_del.called
        assert b"imported" in resp.data.lower()

    @patch("threat_feed_aggregator.routes.system.add_whitelist_item", return_value=(True, "Added"))
    @patch("threat_feed_aggregator.routes.system.delete_whitelisted_indicators")
    def test_import_json_file(self, mock_del, mock_add, auth_client):
        content = json.dumps(["3.3.3.3", "4.4.4.4"]).encode()
        data = {"import_file": (io.BytesIO(content), "indicators.json")}
        resp = auth_client.post(
            "/system/whitelist/import",
            data=data,
            content_type="multipart/form-data",
            follow_redirects=True,
        )
        assert mock_add.call_count == 2


class TestBlacklistImport:
    """POST /system/blacklist/import"""

    @patch("threat_feed_aggregator.aggregator.regenerate_edl_files")
    @patch("threat_feed_aggregator.routes.system.add_api_blacklist_item", return_value=(True, "Added"))
    def test_import_text_file(self, mock_add, mock_regen, auth_client):
        content = b"5.5.5.5\n6.6.6.6\n"
        data = {"import_file": (io.BytesIO(content), "blocklist.txt")}
        resp = auth_client.post(
            "/system/blacklist/import",
            data=data,
            content_type="multipart/form-data",
            follow_redirects=True,
        )
        assert mock_add.call_count == 2
        assert mock_regen.called


# ============================================================
# Settings Update
# ============================================================

class TestSettingsUpdate:
    """POST /system/update_settings"""

    @patch("threat_feed_aggregator.routes.system.write_config")
    @patch("threat_feed_aggregator.routes.system.read_config", return_value={
        "indicator_lifetime_days": 30, "timezone": "UTC",
    })
    def test_update_lifetime(self, mock_read, mock_write, auth_client):
        resp = auth_client.post("/system/update_settings", data={
            "indicator_lifetime_days": "60",
            "timezone": "Europe/Istanbul",
        })
        assert resp.status_code == 302
        assert mock_write.called
        config = mock_write.call_args[0][0]
        assert config["indicator_lifetime_days"] == 60
        assert config["timezone"] == "Europe/Istanbul"


# ============================================================
# API Client Management
# ============================================================

class TestAPIClientManagement:
    """API client CRUD via /system/api_client/*"""

    @patch("threat_feed_aggregator.routes.system.write_config")
    @patch("threat_feed_aggregator.routes.system.read_config", return_value={"api_clients": []})
    def test_add_client(self, mock_read, mock_write, auth_client):
        resp = auth_client.post("/system/api_client/add", data={
            "name": "TestClient",
            "allowed_ips": "10.0.0.1, 10.0.0.2",
        })
        assert resp.status_code == 302
        assert mock_write.called
        config = mock_write.call_args[0][0]
        assert len(config["api_clients"]) == 1
        client_data = config["api_clients"][0]
        assert client_data["name"] == "TestClient"
        assert len(client_data["api_key"]) == 32
        assert "10.0.0.1" in client_data["allowed_ips"]

    @patch("threat_feed_aggregator.routes.system.write_config")
    @patch("threat_feed_aggregator.routes.system.read_config", return_value={
        "api_clients": [{"id": "abc-123", "name": "OldClient", "api_key": "oldkey"}]
    })
    def test_remove_client(self, mock_read, mock_write, auth_client):
        resp = auth_client.post("/system/api_client/remove", data={
            "client_id": "abc-123",
        })
        assert resp.status_code == 302
        assert mock_write.called
        config = mock_write.call_args[0][0]
        assert len(config["api_clients"]) == 0


# ============================================================
# Proxy Settings
# ============================================================

class TestProxySettings:
    """POST /system/update_proxy"""

    @patch("threat_feed_aggregator.routes.system.write_config")
    @patch("threat_feed_aggregator.routes.system.read_config", return_value={})
    def test_update_proxy(self, mock_read, mock_write, auth_client):
        resp = auth_client.post("/system/update_proxy", data={
            "proxy_enabled": "on",
            "proxy_server": "proxy.example.com",
            "proxy_port": "8080",
            "proxy_username": "user",
            "proxy_password": "pass",
        })
        assert resp.status_code == 302
        assert mock_write.called
        config = mock_write.call_args[0][0]
        assert config["proxy"]["enabled"] is True
        assert config["proxy"]["server"] == "proxy.example.com"
        assert config["proxy"]["port"] == "8080"

    @patch("threat_feed_aggregator.routes.system.write_config")
    @patch("threat_feed_aggregator.routes.system.read_config", return_value={})
    def test_disable_proxy(self, mock_read, mock_write, auth_client):
        resp = auth_client.post("/system/update_proxy", data={
            "proxy_server": "proxy.example.com",
            "proxy_port": "8080",
        })
        assert resp.status_code == 302
        assert mock_write.called
        config = mock_write.call_args[0][0]
        assert config["proxy"]["enabled"] is False


# ============================================================
# Admin Profile Management
# ============================================================

class TestAdminProfiles:
    """Profile CRUD via /system/admin_profiles/*"""

    @patch("threat_feed_aggregator.routes.system.add_admin_profile", return_value=(True, "Created"))
    def test_add_profile(self, mock_add, auth_client):
        perms = json.dumps({"dashboard": "rw", "system": "r", "tools": "r"})
        resp = auth_client.post("/system/admin_profiles/add", data={
            "name": "Analyst",
            "description": "Read-only analyst",
            "permissions": perms,
        }, follow_redirects=True)
        assert mock_add.called
        assert b"added successfully" in resp.data

    def test_invalid_permissions_json(self, auth_client):
        resp = auth_client.post("/system/admin_profiles/add", data={
            "name": "Bad",
            "permissions": "not-valid-json{{{",
        }, follow_redirects=True)
        assert b"Invalid permissions" in resp.data

    @patch("threat_feed_aggregator.routes.system.delete_admin_profile", return_value=(True, "Deleted"))
    def test_delete_profile(self, mock_del, auth_client):
        resp = auth_client.post("/system/admin_profiles/delete", data={
            "profile_id": 99,
        }, follow_redirects=True)
        assert mock_del.called
        assert b"deleted" in resp.data


# ============================================================
# LDAP Management
# ============================================================

class TestLDAPSettings:
    """POST /system/update_ldap"""

    @patch("threat_feed_aggregator.routes.system.write_config")
    @patch("threat_feed_aggregator.routes.system.read_config", return_value={"auth": {}})
    def test_update_ldap_config(self, mock_read, mock_write, auth_client):
        resp = auth_client.post("/system/update_ldap", data={
            "ldap_enabled": "on",
            "ldap_server[]": ["dc1.example.com", "dc2.example.com"],
            "ldap_port": "636",
            "ldap_domain": "DC=example,DC=com",
            "ldap_admin_group": "Domain Admins",
            "ldaps_enabled": "on",
        })
        assert resp.status_code == 302
        assert mock_write.called
        config = mock_write.call_args[0][0]
        assert config["auth"]["ldap_enabled"] is True
        assert len(config["auth"]["ldap_servers"]) == 2
        assert config["auth"]["ldap_servers"][0]["ldaps_enabled"] is True


# ============================================================
# Certificate Upload
# ============================================================

class TestCertUpload:
    """POST /system/upload_cert, /system/upload_root_ca"""

    def test_upload_cert_requires_file(self, auth_client):
        resp = auth_client.post("/system/upload_cert", follow_redirects=True)
        assert b"No file part" in resp.data

    def test_upload_root_ca_requires_file(self, auth_client):
        resp = auth_client.post("/system/upload_root_ca", follow_redirects=True)
        assert b"No file part" in resp.data

    @patch("threat_feed_aggregator.routes.system.process_root_ca_upload", return_value=(True, "Trusted"))
    def test_root_ca_upload_success(self, mock_upload, auth_client):
        cert_data = b"-----BEGIN CERTIFICATE-----\nMIIBxTCCAW...\n-----END CERTIFICATE-----"
        resp = auth_client.post(
            "/system/upload_root_ca",
            data={"ca_file": (io.BytesIO(cert_data), "ca.pem")},
            content_type="multipart/form-data",
            follow_redirects=True,
        )
        assert mock_upload.called
        assert b"Trusted" in resp.data or b"restart" in resp.data.lower()


# ============================================================
# Custom EDL Lists
# ============================================================

class TestCustomLists:
    """Custom EDL list CRUD"""

    @patch("threat_feed_aggregator.routes.system.create_custom_list", return_value=(1, "abc123"))
    def test_create_custom_list(self, mock_create, auth_client):
        resp = auth_client.post("/system/custom_lists/add", data={
            "name": "Test EDL",
            "format": "text",
            "sources": ["Source1", "Source2"],
            "content_type": "ip",
        }, follow_redirects=True)
        assert mock_create.called
        assert b"created successfully" in resp.data

    @patch("threat_feed_aggregator.routes.system.delete_custom_list", return_value=True)
    def test_delete_custom_list(self, mock_del, auth_client):
        resp = auth_client.post("/system/custom_lists/delete", data={
            "list_id": 1,
        }, follow_redirects=True)
        assert mock_del.called
        assert b"deleted" in resp.data
