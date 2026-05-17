"""Specter-Net: Stealth threat detection for Obsidian Labs."""
from .events import ThreatEvent, TelemetryEvent
from .monitors import SyscallMonitor, NetworkMonitor, MemoryMonitor
from .pipeline import EventPipeline
from .detectors import InjectionDetector, LateralMovementDetector, C2Detector

__version__ = "0.1.0"
