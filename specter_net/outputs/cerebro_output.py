"""Send telemetry to cerebro for ML analysis."""
import logging
from ..events import TelemetryEvent, ThreatEvent

logger = logging.getLogger("specter-net.output.cerebro")

class CerebroOutput:
    """Forward raw telemetry and threat events to cerebro ML engine."""

    def __init__(self, endpoint: str = "localhost:9091"):
        self.endpoint = endpoint
        self.telemetry_sent = 0
        self.threats_sent = 0

    def send_telemetry(self, event: TelemetryEvent):
        logger.debug(f"-> cerebro: telemetry {event.event_type}")
        self.telemetry_sent += 1

    def send_threat(self, event: ThreatEvent):
        logger.info(f"-> cerebro: threat {event.event_type} (conf={event.confidence})")
        self.threats_sent += 1

    def get_stats(self) -> dict:
        return {"telemetry_sent": self.telemetry_sent, "threats_sent": self.threats_sent}
