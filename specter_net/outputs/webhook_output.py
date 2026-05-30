"""Webhook output for SIEM/alerting integration."""
import json
import logging
from ..events import ThreatEvent

logger = logging.getLogger("specter-net.output.webhook")

class WebhookOutput:
    """Send alerts via webhook (Slack, PagerDuty, etc.)."""

    def __init__(self, urls: list = None):
        self.urls = urls or []
        self.alerts_sent = 0

    def send(self, event: ThreatEvent):
        payload = {
            "text": f":rotating_light: *{event.severity.value.upper()}*: {event.event_type}",
            "blocks": [
                {"type": "section", "text": {"type": "mrkdwn", "text": f"*Threat Detected*\nType: {event.event_type}\nSeverity: {event.severity.value}\nConfidence: {event.confidence:.0%}\nPID: {event.target_pid}"}},
            ],
        }
        logger.info(f"Webhook alert: {event.event_type} -> {len(self.urls)} endpoints")
        self.alerts_sent += 1
