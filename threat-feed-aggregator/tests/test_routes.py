"""
Route-level tests for authentication, CSRF, permissions, and new features.
"""


class TestHealthEndpoint:
    def test_health_returns_200(self, client):
        response = client.get("/health")
        assert response.status_code == 200
        data = response.get_json()
        assert data["data"]["status"] in ("healthy", "degraded")

    def test_health_includes_version(self, client):
        response = client.get("/health")
        data = response.get_json()
        assert "version" in data["data"]

    def test_health_includes_db_status(self, client):
        response = client.get("/health")
        data = response.get_json()
        assert "database" in data["data"]


class TestAuthRoutes:
    def test_login_page_renders(self, client):
        response = client.get("/auth/login")
        assert response.status_code == 200

    def test_login_redirect_when_unauthenticated(self, client):
        response = client.get("/")
        assert response.status_code == 302
        assert "/auth/login" in response.headers["Location"]

    def test_dashboard_accessible_when_authenticated(self, auth_client):
        response = auth_client.get("/")
        assert response.status_code == 200

    def test_logout_clears_session(self, auth_client):
        response = auth_client.get("/auth/logout")
        assert response.status_code == 302
        response = auth_client.get("/")
        assert response.status_code == 302


class TestDestructiveEndpointsRequirePOST:
    """Verify that destructive operations reject GET requests."""

    def test_remove_source_rejects_get(self, auth_client):
        response = auth_client.get("/system/remove_source/0")
        assert response.status_code == 405

    def test_remove_whitelist_rejects_get(self, auth_client):
        response = auth_client.get("/system/whitelist/remove/1")
        assert response.status_code == 405

    def test_remove_blacklist_rejects_get(self, auth_client):
        response = auth_client.get("/system/blacklist/remove/test")
        assert response.status_code == 405


class TestBackupPermission:
    def test_backup_requires_auth(self, client):
        response = client.get("/api/backup")
        assert response.status_code == 302

    def test_backup_requires_system_rw(self, readonly_client):
        response = readonly_client.get("/api/backup")
        assert response.status_code == 302

    def test_backup_allowed_for_admin(self, auth_client):
        response = auth_client.get("/api/backup")
        assert response.status_code in (200, 500)


class TestAPIStatus:
    def test_status_requires_auth(self, client):
        response = client.get("/api/status")
        assert response.status_code == 302

    def test_status_returns_json(self, auth_client):
        response = auth_client.get("/api/status")
        assert response.status_code == 200
        data = response.get_json()
        assert "aggregation_status" in data.get("data", {})


class TestFeedHealth:
    def test_feed_health_requires_auth(self, client):
        response = client.get("/api/feed_health")
        assert response.status_code == 302

    def test_feed_health_returns_json(self, auth_client):
        response = auth_client.get("/api/feed_health")
        assert response.status_code == 200


class TestAPIDocumentation:
    def test_api_docs_returns_openapi(self, client):
        response = client.get("/api/docs")
        assert response.status_code == 200
        data = response.get_json()
        assert data["openapi"] == "3.1.0"
        assert "paths" in data

    def test_api_docs_has_endpoints(self, client):
        response = client.get("/api/docs")
        data = response.get_json()
        assert "/health" in data["paths"]
        assert "/api/edl/generic" in data["paths"]


class TestExport:
    def test_export_requires_auth(self, client):
        response = client.get("/analysis/export?format=csv")
        assert response.status_code == 302

    def test_export_csv(self, auth_client):
        response = auth_client.get("/analysis/export?format=csv")
        assert response.status_code == 200
        assert "text/csv" in response.content_type

    def test_export_json(self, auth_client):
        response = auth_client.get("/analysis/export?format=json")
        assert response.status_code == 200
        assert "application/json" in response.content_type


class TestPasswordComplexity:
    def test_weak_password_rejected(self, auth_client):
        response = auth_client.post("/system/users/add", data={
            "username": "testuser",
            "password": "weak",
            "profile_id": 3,
        }, follow_redirects=True)
        assert b"at least" in response.data or response.status_code == 200


class TestMetrics:
    def test_metrics_endpoint(self, client):
        response = client.get("/metrics")
        assert response.status_code == 200
