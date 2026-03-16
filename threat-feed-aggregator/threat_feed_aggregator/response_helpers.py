"""
Standard API response helpers for consistent JSON output.

All API endpoints should use these helpers instead of raw jsonify()
to ensure uniform response format across the application.

Untouched endpoints (raw output, no envelope):
- GET /api/edl/firewall/<file>   (plain text for firewalls)
- GET /api/edl/custom/<token>    (text/csv/json by format)
- GET /api/edl/generic           (streaming text/csv/json)
- POST /api/deceptor/block       (FortiDeceptor integration)
- POST /api/deceptor/unblock     (FortiDeceptor integration)
"""

from datetime import UTC, datetime

from flask import jsonify


def api_response(data=None, message=None, status=200):
    """Return a standardized success response.

    Args:
        data: Response payload (dict, list, or scalar).
        message: Optional human-readable message.
        status: HTTP status code (default 200).

    Returns:
        Flask Response with JSON body and status code.
    """
    body = {
        "status": "success",
        "timestamp": datetime.now(UTC).isoformat(),
    }
    if data is not None:
        body["data"] = data
    if message:
        body["message"] = message
    return jsonify(body), status


def api_error(message, code="UNKNOWN_ERROR", status=400):
    """Return a standardized error response.

    Args:
        message: Human-readable error description.
        code: Machine-readable error code (e.g. VALIDATION_ERROR).
        status: HTTP status code (default 400).

    Returns:
        Flask Response with JSON body and status code.
    """
    return jsonify({
        "status": "error",
        "message": message,
        "code": code,
        "timestamp": datetime.now(UTC).isoformat(),
    }), status
