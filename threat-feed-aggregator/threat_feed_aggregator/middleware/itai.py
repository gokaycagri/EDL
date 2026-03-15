"""
ITAI Hub integration middleware.

Activated only when ITAI_MODE=true environment variable is set.
Provides:
  1. Trace ID propagation (X-ITAI-Trace-ID header)
  2. SSO auto-login endpoint (POST /auth/sso)
  3. iframe-compatible session cookie settings

When ITAI_MODE is not set or false, this middleware does nothing and
the application behaves as a standalone deployment.
"""

import hmac
import hashlib
import json
import logging
import os
import time
from base64 import urlsafe_b64decode
from contextvars import ContextVar

from flask import Blueprint, jsonify, request, session

from ..response_helpers import api_error, api_response

logger = logging.getLogger(__name__)

# --- Configuration ---

ITAI_MODE = os.environ.get("ITAI_MODE", "false").lower() == "true"
ITAI_JWT_SECRET = os.environ.get("ITAI_JWT_SECRET", "")

# Context variable for trace ID propagation across async boundaries
trace_id_var: ContextVar[str | None] = ContextVar("trace_id", default=None)

# Blueprint for SSO endpoint
bp_itai = Blueprint("itai", __name__)


# --- Trace ID Middleware ---

def register_itai_middleware(app):
    """Register ITAI middleware hooks on the Flask app.

    Call this once during app initialization. The SSO blueprint is always
    registered (returns 403 when ITAI_MODE=false). Trace ID and cookie
    hooks are only active when ITAI_MODE=true.
    """
    # Always register the SSO blueprint so the route exists
    app.register_blueprint(bp_itai)

    if not ITAI_MODE:
        logger.info("ITAI_MODE is disabled — middleware inactive (SSO endpoint returns 403).")
        return

    logger.info("ITAI_MODE is enabled — registering middleware.")

    # iframe cookie settings
    app.config["SESSION_COOKIE_SAMESITE"] = "None"
    app.config["SESSION_COOKIE_SECURE"] = True

    @app.before_request
    def _extract_trace_id():
        tid = request.headers.get("X-ITAI-Trace-ID")
        if tid:
            trace_id_var.set(tid)

    @app.after_request
    def _inject_trace_id(response):
        tid = trace_id_var.get(None)
        if tid:
            response.headers["X-ITAI-Trace-ID"] = tid
        return response

    # SSO blueprint already registered above


# --- JWT Helpers (HS256 only, minimal) ---

def _b64decode(data: str) -> bytes:
    """Decode URL-safe base64 with padding."""
    padding = 4 - len(data) % 4
    if padding != 4:
        data += "=" * padding
    return urlsafe_b64decode(data)


def _verify_hs256_token(token: str, secret: str) -> dict | None:
    """Verify a HS256 JWT and return payload, or None on failure.

    This is a minimal verifier — no external JWT library required.
    Checks signature and expiration only.
    """
    try:
        parts = token.split(".")
        if len(parts) != 3:
            return None

        header_b = _b64decode(parts[0])
        payload_b = _b64decode(parts[1])
        signature = _b64decode(parts[2])

        header = json.loads(header_b)
        if header.get("alg") != "HS256":
            logger.warning(f"SSO token uses unsupported algorithm: {header.get('alg')}")
            return None

        # Verify signature
        signing_input = f"{parts[0]}.{parts[1]}".encode()
        expected_sig = hmac.new(
            secret.encode(), signing_input, hashlib.sha256
        ).digest()

        if not hmac.compare_digest(signature, expected_sig):
            return None

        payload = json.loads(payload_b)

        # Check expiration
        exp = payload.get("exp")
        if exp and time.time() > exp:
            logger.warning("SSO token expired.")
            return None

        return payload
    except Exception as e:
        logger.warning(f"SSO token verification failed: {e}")
        return None


# --- SSO Endpoint ---

@bp_itai.route("/auth/sso", methods=["POST"])
def sso_login():
    """SSO auto-login for ITAI Hub iframe integration.

    Expects: Authorization: Bearer <jwt>
    The JWT is verified using ITAI_JWT_SECRET (HS256).
    On success, creates a Flask session with Super_User permissions.
    """
    if not ITAI_MODE:
        return api_error("SSO disabled", "SSO_DISABLED", 403)

    auth_header = request.headers.get("Authorization", "")
    if not auth_header.startswith("Bearer "):
        return api_error("Missing Bearer token", "SSO_MISSING_TOKEN", 401)

    token = auth_header[7:]  # Strip "Bearer "

    if not ITAI_JWT_SECRET:
        logger.error("ITAI_JWT_SECRET not configured — cannot verify SSO token.")
        return api_error("SSO not configured", "SSO_NOT_CONFIGURED", 500)

    payload = _verify_hs256_token(token, ITAI_JWT_SECRET)
    if payload is None:
        return api_error("Invalid or expired token", "SSO_INVALID_TOKEN", 401)

    # Create Flask session
    username = payload.get("preferred_username") or payload.get("sub", "itai_user")
    session["logged_in"] = True
    session["username"] = username
    session["permissions"] = {
        "dashboard": "rw",
        "system": "rw",
        "tools": "rw",
        "analysis": "rw",
    }
    session["profile_name"] = "ITAI SSO"

    logger.info(f"SSO login successful for user: {username}")
    return api_response({"session": "created", "username": username})


# --- Utility ---

def get_trace_id() -> str | None:
    """Get current trace ID from context (for use in logging)."""
    return trace_id_var.get(None)
