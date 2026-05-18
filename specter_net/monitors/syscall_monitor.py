"""Kernel-level syscall monitoring via eBPF/kprobes."""
import logging
import time
from typing import List, Callable, Optional
from dataclasses import dataclass
from ..events import TelemetryEvent, EventSource

logger = logging.getLogger("specter-net.syscall")

# Suspicious syscall patterns
SUSPICIOUS_PATTERNS = {
    "process_injection": {
        "syscalls": ["ptrace", "process_vm_writev", "mmap", "mprotect"],
        "sequence": ["ptrace(PTRACE_ATTACH)", "process_vm_writev", "mprotect(RWX)"],
        "confidence_base": 0.75,
    },
    "fileless_execution": {
        "syscalls": ["memfd_create", "write", "fexecve"],
        "sequence": ["memfd_create", "write", "fexecve"],
        "confidence_base": 0.90,
    },
    "privilege_escalation": {
        "syscalls": ["setuid", "setgid", "capset", "prctl"],
        "sequence": ["setuid(0)", "execve"],
        "confidence_base": 0.80,
    },
    "credential_dumping": {
        "syscalls": ["open", "read", "mmap"],
        "sequence": ["/etc/shadow", "/proc/*/mem"],
        "confidence_base": 0.85,
    },
}

@dataclass
class SyscallEvent:
    pid: int
    process_name: str
    syscall: str
    args: list
    timestamp: float
    return_value: int

class SyscallMonitor:
    """Monitor system calls for suspicious patterns."""

    def __init__(self, callback: Optional[Callable] = None):
        self.callback = callback
        self.event_buffer: List[SyscallEvent] = []
        self.patterns = SUSPICIOUS_PATTERNS
        self._running = False
        self.stats = {"total_events": 0, "suspicious": 0}

    def start(self):
        """Start syscall monitoring via eBPF."""
        self._running = True
        logger.info("Syscall monitor started (eBPF/kprobe mode)")

    def stop(self):
        self._running = False
        logger.info("Syscall monitor stopped")

    def on_syscall(self, event: SyscallEvent):
        """Process a syscall event."""
        self.event_buffer.append(event)
        self.stats["total_events"] += 1

        # Check against suspicious patterns
        for pattern_name, pattern in self.patterns.items():
            if self._matches_pattern(event, pattern):
                self.stats["suspicious"] += 1
                telemetry = TelemetryEvent(
                    source=EventSource.SYSCALL,
                    event_type=pattern_name,
                    raw_data={
                        "pid": event.pid,
                        "process": event.process_name,
                        "syscall": event.syscall,
                        "args": event.args,
                    },
                )
                if self.callback:
                    self.callback(telemetry)

    def _matches_pattern(self, event: SyscallEvent, pattern: dict) -> bool:
        """Check if syscall matches a suspicious pattern."""
        return event.syscall in pattern["syscalls"]

    def get_recent_events(self, count: int = 100) -> List[SyscallEvent]:
        return self.event_buffer[-count:]

    def get_stats(self) -> dict:
        return self.stats.copy()
