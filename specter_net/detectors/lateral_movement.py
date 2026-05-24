"""Lateral movement detection — SMB, PSRemoting, WMI abuse."""
import logging
import time
from typing import Optional, Dict, List
from collections import defaultdict
from ..events import TelemetryEvent, ThreatEvent, Severity

logger = logging.getLogger("specter-net.lateral")

# Lateral movement indicators
INDICATORS = {
    "smb_traversal": {
        "ports": [445, 139],
        "tools": ["psexec", "wmic", "smbclient"],
        "severity": Severity.HIGH,
        "confidence": 0.80,
    },
    "ps_remoting": {
        "ports": [5985, 5986],
        "tools": ["powershell", "pwsh"],
        "severity": Severity.HIGH,
        "confidence": 0.75,
    },
    "wmi_execution": {
        "ports": [135],
        "tools": ["wmic", "powershell"],
        "severity": Severity.HIGH,
        "confidence": 0.78,
    },
    "rdp_hop": {
        "ports": [3389],
        "tools": ["mstsc", "xfreerdp"],
        "severity": Severity.MEDIUM,
        "confidence": 0.65,
    },
    "ssh_lateral": {
        "ports": [22],
        "tools": ["ssh", "scp"],
        "severity": Severity.MEDIUM,
        "confidence": 0.50,
    },
}

class LateralMovementDetector:
    """Detect lateral movement via network flow analysis."""

    def __init__(self):
        self.connection_graph: Dict[str, List[str]] = defaultdict(list)
        self.first_seen: Dict[str, float] = {}
        self.host_pairs: Dict[str, int] = defaultdict(int)

    def detect(self, event: TelemetryEvent) -> Optional[ThreatEvent]:
        """Detect lateral movement from telemetry."""
        if event.source.value == "network_monitor":
            return self._analyze_network(event)
        if event.source.value == "syscall_monitor":
            return self._analyze_syscall(event)
        return None

    def _analyze_network(self, event: TelemetryEvent) -> Optional[ThreatEvent]:
        dst_port = event.raw_data.get("dst_port", 0)
        src_ip = event.raw_data.get("src_ip", "")
        dst_ip = event.raw_data.get("dst_ip", "")

        # Update connection graph
        pair_key = f"{src_ip}->{dst_ip}"
        self.host_pairs[pair_key] += 1
        self.connection_graph[src_ip].append(dst_ip)

        # Check suspicious port usage
        for technique, ind in INDICATORS.items():
            if dst_port in ind["ports"]:
                # Multiple hosts from same source = suspicious
                unique_targets = len(set(self.connection_graph.get(src_ip, [])))
                if unique_targets >= 3:
                    return ThreatEvent(
                        source="specter-net",
                        severity=ind["severity"],
                        event_type="lateral_movement",
                        confidence=min(ind["confidence"] + 0.10, 0.99),
                        details={
                            "technique": technique,
                            "src_ip": src_ip,
                            "dst_ip": dst_ip,
                            "dst_port": dst_port,
                            "unique_targets": unique_targets,
                        },
                        indicators=[f"port:{dst_port}", f"targets:{unique_targets}"],
                        recommended_action="isolate",
                    )
        return None

    def _analyze_syscall(self, event: TelemetryEvent) -> Optional[ThreatEvent]:
        syscall = event.raw_data.get("syscall", "")
        process = event.raw_data.get("process", "").lower()

        for technique, ind in INDICATORS.items():
            if any(tool in process for tool in ind["tools"]):
                return ThreatEvent(
                    source="specter-net",
                    severity=ind["severity"],
                    event_type="lateral_movement",
                    target_pid=event.raw_data.get("pid"),
                    confidence=ind["confidence"],
                    details={"technique": technique, "process": process, "syscall": syscall},
                    recommended_action="quarantine",
                )
        return None
