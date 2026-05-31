"""Tests for threat detectors."""
import time
import pytest
from specter_net.events import TelemetryEvent, EventSource
from specter_net.detectors.injection import InjectionDetector
from specter_net.detectors.c2_detector import C2Detector

class TestInjectionDetector:
    def setup_method(self):
        self.det = InjectionDetector()

    def test_process_hollowing_detected(self):
        for syscall in ["NtUnmapViewOfSection", "NtWriteVirtualMemory", "NtResumeThread"]:
            event = TelemetryEvent(source=EventSource.SYSCALL, raw_data={"pid": 100, "syscall": syscall, "process": "malware.exe"})
            result = self.det.detect(event)
        assert result is not None
        assert result.event_type == "process_injection"

    def test_no_injection_on_normal_syscalls(self):
        for syscall in ["read", "write", "open", "close"]:
            event = TelemetryEvent(source=EventSource.SYSCALL, raw_data={"pid": 100, "syscall": syscall})
            result = self.det.detect(event)
        assert result is None

class TestC2Detector:
    def setup_method(self):
        self.det = C2Detector(min_samples=3, max_jitter=0.3)

    def test_beacon_detected(self):
        # Regular 10s intervals = beacon
        for i in range(10):
            event = TelemetryEvent(source=EventSource.NETWORK, raw_data={
                "dst_ip": "10.0.0.1", "timestamp": i * 10.0, "bytes_sent": 1024
            })
            result = self.det.detect(event)
        # Should detect beacon pattern
        assert result is not None
