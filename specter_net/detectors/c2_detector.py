"""C2 (Command & Control) beacon detection via timing analysis."""
import math
import time
import logging
from typing import Optional, Dict, List
from collections import defaultdict
from ..events import TelemetryEvent, ThreatEvent, Severity

logger = logging.getLogger("specter-net.c2")

class C2Detector:
    """Detect C2 beacon patterns through statistical analysis."""

    def __init__(self, min_samples: int = 8, max_jitter: float = 0.20):
        self.min_samples = min_samples
        self.max_jitter = max_jitter
        self.connections: Dict[str, List[float]] = defaultdict(list)
        self.bytes_per_conn: Dict[str, List[int]] = defaultdict(list)

    def detect(self, event: TelemetryEvent) -> Optional[ThreatEvent]:
        """Detect C2 beacon from network telemetry."""
        if event.source.value != "network_monitor":
            return None

        dst_ip = event.raw_data.get("dst_ip", "")
        timestamp = event.raw_data.get("timestamp", time.time())
        bytes_out = event.raw_data.get("bytes_sent", 0)

        self.connections[dst_ip].append(timestamp)
        self.bytes_per_conn[dst_ip].append(bytes_out)

        if len(self.connections[dst_ip]) < self.min_samples:
            return None

        return self._analyze_timing(dst_ip)

    def _analyze_timing(self, dst_ip: str) -> Optional[ThreatEvent]:
        """Analyze connection timing for beacon patterns."""
        times = self.connections[dst_ip][-20:]  # Last 20 connections
        intervals = [times[i+1] - times[i] for i in range(len(times)-1)]
        intervals = [i for i in intervals if i > 0.1]  # Filter too-fast

        if len(intervals) < self.min_samples - 1:
            return None

        avg_interval = sum(intervals) / len(intervals)
        if avg_interval < 0.5:
            return None

        # Calculate jitter (coefficient of variation)
        variance = sum((x - avg_interval) ** 2 for x in intervals) / len(intervals)
        std_dev = math.sqrt(variance)
        jitter = std_dev / avg_interval

        if jitter < self.max_jitter:
            # Check byte size consistency
            bytes_list = self.bytes_per_conn[dst_ip][-20:]
            avg_bytes = sum(bytes_list) / len(bytes_list) if bytes_list else 0

            confidence = min(0.70 + (1 - jitter) * 0.25, 0.99)

            return ThreatEvent(
                source="specter-net",
                severity=Severity.CRITICAL,
                event_type="c2_beacon",
                confidence=confidence,
                details={
                    "dst_ip": dst_ip,
                    "interval": round(avg_interval, 2),
                    "jitter": round(jitter, 4),
                    "samples": len(intervals),
                    "avg_bytes": int(avg_bytes),
                },
                indicators=[f"interval:{avg_interval:.1f}s", f"jitter:{jitter:.4f}"],
                recommended_action="block_and_alert",
            )
        return None
