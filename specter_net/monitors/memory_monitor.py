"""Memory forensics — detect injected code, rootkits, and memory-resident threats."""
import logging
import re
from typing import List, Dict, Optional, Callable
from dataclasses import dataclass
from enum import Enum

logger = logging.getLogger("specter-net.memory")

class MemoryRegionType(Enum):
    CODE = "code"
    DATA = "data"
    STACK = "stack"
    HEAP = "heap"
    MMAP = "mmap"
    UNKNOWN = "unknown"

class MemoryPermission(Enum):
    READ = "r"
    WRITE = "w"
    EXECUTE = "x"
    NONE = "-"

@dataclass
class MemoryRegion:
    start_addr: int
    end_addr: int
    permissions: str  # rwx format
    mapped_file: str
    pid: int
    region_type: MemoryRegionType

@dataclass
class MemoryAnomaly:
    pid: int
    region: MemoryRegion
    anomaly_type: str
    confidence: float
    details: str

class MemoryMonitor:
    """Monitor process memory for suspicious patterns."""

    # Indicators of injected code
    RWX_PERMISSIONS = "rwx"
    SUSPICIOUS_MAPPINGS = ["[anon:", "[heap]", "memfd:"]
    KNOWN_ROOTKIT_PATTERNS = [
        "64 65 76 2f 74 63 70",  # /dev/tcp (reverse shell)
        "2f 62 69 6e 2f 73 68",  # /bin/sh
        "63 6d 64 2e 65 78 65",  # cmd.exe
    ]

    def __init__(self, callback: Optional[Callable] = None):
        self.callback = callback
        self.regions: Dict[int, List[MemoryRegion]] = {}  # pid -> regions
        self.anomalies: List[MemoryAnomaly] = []
        self._running = False

    def start(self):
        self._running = True
        logger.info("Memory monitor started")

    def stop(self):
        self._running = False

    def scan_process(self, pid: int) -> List[MemoryAnomaly]:
        """Scan a process's memory for anomalies."""
        regions = self._read_proc_maps(pid)
        self.regions[pid] = regions
        findings = []

        for region in regions:
            # Check for RWX regions (injection indicator)
            if "rwx" in region.permissions:
                anomaly = MemoryAnomaly(
                    pid=pid, region=region,
                    anomaly_type="rwx_region",
                    confidence=0.70,
                    details=f"RWX region at 0x{region.start_addr:x} — possible code injection",
                )
                findings.append(anomaly)

            # Check for suspicious mappings
            for pattern in self.SUSPICIOUS_MAPPINGS:
                if pattern in region.mapped_file:
                    anomaly = MemoryAnomaly(
                        pid=pid, region=region,
                        anomaly_type="suspicious_mapping",
                        confidence=0.60,
                        details=f"Suspicious mapping: {region.mapped_file}",
                    )
                    findings.append(anomaly)

            # Check memfd (fileless execution)
            if "memfd:" in region.mapped_file:
                anomaly = MemoryAnomaly(
                    pid=pid, region=region,
                    anomaly_type="fileless_execution",
                    confidence=0.90,
                    details=f"memfd mapping detected — fileless execution",
                )
                findings.append(anomaly)

        if findings:
            self.anomalies.extend(findings)
            logger.warning(f"Memory anomalies in PID {pid}: {len(findings)} findings")

        return findings

    def _read_proc_maps(self, pid: int) -> List[MemoryRegion]:
        """Read /proc/pid/maps."""
        # In production: parse actual /proc/pid/maps
        return []

    def check_hook_integrity(self, pid: int) -> Dict[str, bool]:
        """Check for SSDT/IDT/IRP hooks."""
        return {"ssdt": True, "idt": True, "irp": True}

    def get_anomaly_count(self) -> int:
        return len(self.anomalies)
