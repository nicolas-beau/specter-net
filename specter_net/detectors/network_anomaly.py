"""Network anomaly detection via statistical baselines."""
import math, logging
from typing import Dict, Optional
from collections import defaultdict
from ..events import TelemetryEvent, ThreatEvent, Severity

logger = logging.getLogger("specter-net.network_anomaly")

class NetworkAnomalyDetector:
    def __init__(self, window=100, threshold=3.0):
        self.window = window
        self.threshold = threshold
        self.baselines: Dict[str, list] = defaultdict(list)

    def detect(self, event: TelemetryEvent) -> Optional[ThreatEvent]:
        if event.source.value != "network_monitor": return None
        dst_ip = event.raw_data.get("dst_ip", "")
        bytes_out = event.raw_data.get("bytes_sent", 0)
        key = f"{dst_ip}:bytes"
        self.baselines[key].append(bytes_out)
        if len(self.baselines[key]) > self.window:
            self.baselines[key] = self.baselines[key][-self.window:]
        samples = self.baselines[key]
        if len(samples) < 10: return None
        mean = sum(samples) / len(samples)
        std = math.sqrt(sum((x - mean)**2 for x in samples) / len(samples))
        if std == 0: return None
        z = abs(bytes_out - mean) / std
        if z > self.threshold:
            return ThreatEvent(source="specter-net", severity=Severity.MEDIUM, event_type="network_anomaly", confidence=min(0.60 + z * 0.1, 0.95), details={"dst_ip": dst_ip, "z_score": z})
        return None
