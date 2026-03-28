"""
Webhook notification service — fire-and-forget HTTP POST to configured webhook URLs.
"""
from datetime import UTC, datetime
import logging
import threading

import requests

from ..config_manager import read_config

logger = logging.getLogger(__name__)

WEBHOOK_TIMEOUT = 5  # seconds


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
