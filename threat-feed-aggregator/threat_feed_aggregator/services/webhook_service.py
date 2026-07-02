"""
Webhook notification service — fire-and-forget HTTP POST to configured webhook URLs.
"""

from datetime import UTC, datetime
import ipaddress
import logging
import socket
import threading
from urllib.parse import urlparse

import requests

from ..config_manager import read_config
from ..constants import WEBHOOK_TIMEOUT_SECONDS

# Private/internal IP ranges that webhook URLs must not resolve to (SSRF prevention)
_BLOCKED_NETWORKS = [
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("169.254.0.0/16"),  # link-local / cloud metadata endpoints
    ipaddress.ip_network("::1/128"),
    ipaddress.ip_network("fc00::/7"),
]


def _validate_webhook_url(url: str) -> bool:
    """Return True only if the webhook URL is safe to call.

    Rejects non-http(s) schemes and URLs that resolve to private/internal addresses
    to prevent Server-Side Request Forgery (SSRF) attacks.
    """
    try:
        parsed = urlparse(url)
        if parsed.scheme not in ("http", "https"):
            logger.warning("Webhook URL rejected — unsupported scheme: %r", parsed.scheme)
            return False
        host = parsed.hostname
        if not host:
            logger.warning("Webhook URL rejected — missing hostname: %r", url)
            return False
        ip_str = socket.gethostbyname(host)
        ip = ipaddress.ip_address(ip_str)
        for net in _BLOCKED_NETWORKS:
            if ip in net:
                logger.warning(
                    "Webhook URL blocked — resolves to private/internal address: %s -> %s", host, ip_str
                )
                return False
        return True
    except Exception as e:
        logger.warning("Webhook URL validation failed for %r: %s", url, e)
        return False

logger = logging.getLogger(__name__)

WEBHOOK_TIMEOUT = WEBHOOK_TIMEOUT_SECONDS


def notify(event, data=None):
    """
    Send a webhook notification for the given event.

    Args:
        event: Event name (e.g. 'aggregation_complete', 'high_risk_indicator', 'feed_disabled')
        data: Optional dict with event-specific data
    """
    config = read_config()
    webhooks = config.get("webhooks", [])

    if not webhooks:
        return

    payload = {
        "event": event,
        "timestamp": datetime.now(UTC).isoformat(),
        "data": data or {},
    }

    for hook in webhooks:
        hook_events = hook.get("events", [])
        if hook_events and event not in hook_events:
            continue

        url = hook.get("url")
        if not url:
            continue

        if not _validate_webhook_url(url):
            logger.warning("Skipping webhook '%s': URL failed SSRF safety validation.", hook.get("name", "unnamed"))
            continue

        # Fire-and-forget in a thread
        thread = threading.Thread(
            target=_send_webhook,
            args=(url, payload, hook.get("name", "unnamed")),
            daemon=True,
        )
        thread.start()


def _send_webhook(url, payload, name):
    """Send a single webhook POST request. Never raises."""
    try:
        response = requests.post(
            url,
            json=payload,
            timeout=WEBHOOK_TIMEOUT,
            headers={"Content-Type": "application/json"},
        )
        if response.status_code >= 400:
            logger.warning(f"Webhook '{name}' returned {response.status_code}: {response.text[:100]}")
        else:
            logger.debug(f"Webhook '{name}' sent successfully ({response.status_code})")
    except requests.RequestException as e:
        logger.warning(f"Webhook '{name}' failed: {e}")
