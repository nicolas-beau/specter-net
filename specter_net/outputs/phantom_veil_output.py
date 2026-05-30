"""Send threat events to phantom-veil for quarantine."""
import json
import logging
import urllib.request
from ..events import ThreatEvent

logger = logging.getLogger("specter-net.output.pv")

class PhantomVeilOutput:
    """Forward threat events to phantom-veil quarantine API."""

    def __init__(self, endpoint: str = "localhost:9090"):
        self.endpoint = endpoint
        self.events_sent = 0

    def send(self, event: ThreatEvent):
        """Send threat event to phantom-veil."""
        payload = event.to_phantom_veil_event()
        try:
            # In production: HTTP POST to phantom-veil API
            logger.info(f"-> phantom-veil: {event.event_type} (pid={event.target_pid}, conf={event.confidence})")
            self.events_sent += 1
        except Exception as e:
            logger.error(f"Failed to send to phantom-veil: {e}")

    def get_stats(self) -> dict:
        return {"events_sent": self.events_sent}
