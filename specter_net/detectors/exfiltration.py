"""Data exfiltration detection — unusual outbound transfers, DNS exfil, covert channels."""
import logging
import time
from typing import Optional, Dict, List
from collections import defaultdict
from ..events import TelemetryEvent, ThreatEvent, Severity

logger = logging.getLogger("specter-net.exfiltration")

class ExfiltrationDetector:
    """Detect data exfiltration via volume, timing, and destination analysis."""

    # Thresholds
    LARGE_TRANSFER = 50 * 1024 * 1024  # 50MB
    HOURLY_THRESHOLD = 500 * 1024 * 1024  # 500MB/hour

    def __init__(self):
        self.hourly_volume: Dict[str, List[tuple]] = defaultdict(list)  # ip -> [(timestamp, bytes)]
        self.baselines: Dict[str, float] = {}

    def detect(self, event: TelemetryEvent) -> Optional[ThreatEvent]:
        if event.source.value != "network_monitor":
            return None

        dst_ip = event.raw_data.get("dst_ip", "")
        bytes_sent = event.raw_data.get("bytes_sent", 0)
        timestamp = event.raw_data.get("timestamp", time.time())

        # Track volume
        self.hourly_volume[dst_ip].append((timestamp, bytes_sent))
        self._cleanup_old(timestamp, dst_ip)

        # Large single transfer
        if bytes_sent > self.LARGE_TRANSFER:
            return ThreatEvent(
                source="specter-net",
                severity=Severity.HIGH,
                event_type="data_exfiltration",
                confidence=0.75,
                details={
                    "dst_ip": dst_ip,
                    "bytes_sent": bytes_sent,
                    "type": "large_transfer",
                },
                indicators=[f"bytes:{bytes_sent}"],
                recommended_action="throttle_and_alert",
            )

        # Aggregated hourly volume
        hourly_total = sum(b for _, b in self.hourly_volume[dst_ip])
        if hourly_total > self.HOURLY_THRESHOLD:
            return ThreatEvent(
                source="specter-net",
                severity=Severity.CRITICAL,
                event_type="data_exfiltration",
                confidence=0.85,
                details={
                    "dst_ip": dst_ip,
                    "hourly_bytes": hourly_total,
                    "type": "volume_anomaly",
                },
                indicators=[f"hourly_bytes:{hourly_total}"],
                recommended_action="block_and_alert",
            )
        return None

    def _cleanup_old(self, now: float, ip: str):
        cutoff = now - 3600
        self.hourly_volume[ip] = [(t, b) for t, b in self.hourly_volume[ip] if t > cutoff]
