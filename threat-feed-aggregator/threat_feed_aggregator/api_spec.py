"""
OpenAPI 3.1 specification for the Threat Feed Aggregator API.
Served at /api/docs as JSON.
"""

from .version import __version__

OPENAPI_SPEC = {
    "openapi": "3.1.0",
    "info": {
        "title": "Threat Feed Aggregator API",
        "version": __version__,
        "description": "Enterprise threat intelligence aggregation platform API for managing EDLs, indicators, and integrations.",
    },
    "paths": {
        "/health": {
            "get": {
                "summary": "Health check",
                "tags": ["System"],
                "responses": {"200": {"description": "Service health status with DB and scheduler info"}},
            }
        },
        "/metrics": {
            "get": {
                "summary": "Prometheus metrics",
                "tags": ["System"],
                "responses": {"200": {"description": "Prometheus-formatted metrics"}},
            }
        },
        "/api/edl/firewall/{filename}": {
            "get": {
                "summary": "Download EDL file for firewalls",
                "tags": ["EDL"],
                "parameters": [{"name": "filename", "in": "path", "required": True, "schema": {"type": "string"}}],
                "responses": {"200": {"description": "Plain text EDL file"}},
            }
        },
        "/api/edl/custom/{token}": {
            "get": {
                "summary": "Download custom EDL by token",
                "tags": ["EDL"],
                "parameters": [{"name": "token", "in": "path", "required": True, "schema": {"type": "string"}}],
                "responses": {"200": {"description": "Custom EDL in configured format"}},
            }
        },
        "/api/edl/generic": {
            "get": {
                "summary": "Generic EDL with filters",
                "tags": ["EDL"],
                "security": [{"ApiKey": []}],
                "parameters": [
                    {
                        "name": "types",
                        "in": "query",
                        "schema": {"type": "string"},
                        "description": "Comma-separated: ip,domain,url,cidr",
                    },
                    {"name": "format", "in": "query", "schema": {"type": "string", "enum": ["text", "csv", "json"]}},
                    {
                        "name": "sources",
                        "in": "query",
                        "schema": {"type": "string"},
                        "description": "Comma-separated source names",
                    },
                ],
                "responses": {"200": {"description": "Filtered EDL"}},
            }
        },
        "/api/indicators": {
            "post": {
                "summary": "Add indicator (SOAR integration)",
                "tags": ["SOAR"],
                "security": [{"ApiKey": []}],
                "requestBody": {
                    "content": {
                        "application/json": {
                            "schema": {
                                "type": "object",
                                "properties": {
                                    "type": {"type": "string", "enum": ["whitelist", "blacklist"]},
                                    "value": {"type": "string"},
                                    "comment": {"type": "string"},
                                },
                                "required": ["type", "value"],
                            }
                        }
                    }
                },
                "responses": {"200": {"description": "Indicator added"}},
            },
            "delete": {
                "summary": "Remove indicator",
                "tags": ["SOAR"],
                "security": [{"ApiKey": []}],
                "responses": {"200": {"description": "Indicator removed"}},
            },
        },
        "/api/deceptor/block": {
            "post": {
                "summary": "FortiDeceptor auto-block webhook",
                "tags": ["FortiDeceptor"],
                "security": [{"ApiKey": []}],
                "responses": {"200": {"description": "IP blocked"}},
            }
        },
        "/api/deceptor/unblock": {
            "post": {
                "summary": "FortiDeceptor auto-unblock webhook",
                "tags": ["FortiDeceptor"],
                "security": [{"ApiKey": []}],
                "responses": {"200": {"description": "IP unblocked"}},
            }
        },
        "/api/run": {
            "post": {
                "summary": "Trigger full aggregation",
                "tags": ["Aggregation"],
                "security": [{"Session": []}],
                "responses": {"200": {"description": "Aggregation started"}},
            }
        },
        "/api/status": {
            "get": {
                "summary": "Aggregation status",
                "tags": ["Aggregation"],
                "security": [{"Session": []}],
                "responses": {"200": {"description": "Current aggregation status"}},
            }
        },
        "/api/feed_health": {
            "get": {
                "summary": "Feed health statuses",
                "tags": ["Monitoring"],
                "security": [{"Session": []}],
                "responses": {"200": {"description": "Health status for all feeds"}},
            }
        },
        "/api/backup": {
            "get": {
                "summary": "Download system backup (admin only)",
                "tags": ["System"],
                "security": [{"Session": []}],
                "responses": {"200": {"description": "ZIP archive of config and database"}},
            }
        },
        "/auth/sso": {
            "post": {
                "summary": "ITAI Hub SSO login",
                "tags": ["Auth"],
                "security": [{"Bearer": []}],
                "responses": {"200": {"description": "Session created"}},
            }
        },
    },
    "components": {
        "securitySchemes": {
            "ApiKey": {
                "type": "apiKey",
                "in": "header",
                "name": "Authorization",
                "description": "API key via 'Bearer <key>' or X-API-KEY header",
            },
            "Session": {
                "type": "apiKey",
                "in": "cookie",
                "name": "session",
                "description": "Flask session cookie (login required)",
            },
            "Bearer": {
                "type": "http",
                "scheme": "bearer",
                "bearerFormat": "JWT",
            },
        }
    },
}
