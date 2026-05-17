"""Event definitions for specter-net telemetry."""
import time
import uuid
from typing import Dict, Any, Optional
from dataclasses import dataclass, field
from enum import Enum

class Severity(Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"

class EventSource(Enum):
    SYSCALL = "syscall_monitor"
    NETWORK = "network_monitor"
    MEMORY = "memory_monitor"
    PROCESS = "process_monitor"
    FILE = "file_monitor"

@dataclass
class TelemetryEvent:
    """Raw telemetry event from monitoring."""
    event_id: str = field(default_factory=lambda: uuid.uuid4().hex[:12])
    timestamp: float = field(default_factory=time.time)
    source: EventSource = EventSource.SYSCALL
    event_type: str = ""
    raw_data: Dict[str, Any] = field(default_factory=dict)

@dataclass
class ThreatEvent:
    """Processed threat event with classification."""
    event_id: str = field(default_factory=lambda: uuid.uuid4().hex[:12])
    timestamp: float = field(default_factory=time.time)
    source: str = ""
    severity: Severity = Severity.MEDIUM
    event_type: str = ""
    target_pid: Optional[int] = None
    confidence: float = 0.0
    details: Dict[str, Any] = field(default_factory=dict)
    indicators: list = field(default_factory=list)
    recommended_action: str = "log"

    def to_dict(self) -> dict:
        return {
            "event_id": self.event_id,
            "timestamp": self.timestamp,
            "source": self.source,
            "severity": self.severity.value,
            "event_type": self.event_type,
            "target_pid": self.target_pid,
            "confidence": self.confidence,
            "details": self.details,
            "indicators": self.indicators,
            "recommended_action": self.recommended_action,
        }

    def to_phantom_veil_event(self) -> dict:
        """Format for phantom-veil integration."""
        return {
            "event_id": self.event_id,
            "source": "specter-net",
            "severity": self.severity.value,
            "event_type": self.event_type,
            "target_pid": self.target_pid,
            "confidence": self.confidence,
            "timestamp": self.timestamp,
            "details": self.details,
        }
