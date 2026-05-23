"""Process injection detection — DLL injection, process hollowing, reflective loading."""
import logging
import time
from typing import Optional
from ..events import TelemetryEvent, ThreatEvent, Severity

logger = logging.getLogger("specter-net.injection")

# Attack technique signatures
TECHNIQUES = {
    "process_hollowing": {
        "sequence": ["NtUnmapViewOfSection", "NtWriteVirtualMemory", "NtResumeThread"],
        "confidence": 0.95,
        "severity": Severity.CRITICAL,
    },
    "dll_injection": {
        "sequence": ["OpenProcess", "VirtualAllocEx", "WriteProcessMemory", "CreateRemoteThread"],
        "confidence": 0.90,
        "severity": Severity.HIGH,
    },
    "reflective_loading": {
        "sequence": ["VirtualAlloc", "memfd_create", "write", "dlopen"],
        "confidence": 0.92,
        "severity": Severity.CRITICAL,
    },
    "thread_execution_hijack": {
        "sequence": ["SuspendThread", "GetThreadContext", "SetThreadContext", "ResumeThread"],
        "confidence": 0.88,
        "severity": Severity.HIGH,
    },
    "apc_injection": {
        "sequence": ["OpenThread", "VirtualAllocEx", "WriteProcessMemory", "QueueUserAPC"],
        "confidence": 0.85,
        "severity": Severity.HIGH,
    },
}

class InjectionDetector:
    """Detect process injection techniques."""

    def __init__(self):
        self.techniques = TECHNIQUES
        self.sequence_buffer: dict = {}  # pid -> [recent syscalls]
        self.window_size = 10

    def detect(self, event: TelemetryEvent) -> Optional[ThreatEvent]:
        """Analyze telemetry for injection indicators."""
        if event.source.value != "syscall_monitor":
            return None

        pid = event.raw_data.get("pid", 0)
        syscall = event.raw_data.get("syscall", "")

        # Maintain sequence buffer per process
        self.sequence_buffer.setdefault(pid, []).append(syscall)
        self.sequence_buffer[pid] = self.sequence_buffer[pid][-self.window_size:]

        # Check against known techniques
        for tech_name, tech in self.techniques.items():
            if self._sequence_matches(self.sequence_buffer[pid], tech["sequence"]):
                return ThreatEvent(
                    source="specter-net",
                    severity=tech["severity"],
                    event_type="process_injection",
                    target_pid=pid,
                    confidence=tech["confidence"],
                    details={
                        "technique": tech_name,
                        "detected_sequence": self.sequence_buffer[pid][-5:],
                        "process": event.raw_data.get("process", "unknown"),
                    },
                    indicators=[f"syscall:{s}" for s in tech["sequence"]],
                    recommended_action="quarantine",
                )
        return None

    def _sequence_matches(self, actual: list, pattern: list) -> bool:
        """Check if actual syscall sequence contains pattern as subsequence."""
        if len(actual) < len(pattern):
            return False
        pi = 0
        for syscall in actual:
            if pi < len(pattern) and syscall == pattern[pi]:
                pi += 1
        return pi == len(pattern)

    def reset(self, pid: int = None):
        if pid:
            self.sequence_buffer.pop(pid, None)
        else:
            self.sequence_buffer.clear()
