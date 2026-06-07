"""Full injection detector tests."""
import pytest
from specter_net.events import TelemetryEvent, EventSource
from specter_net.detectors.injection import InjectionDetector, TECHNIQUES

class TestInjectionFull:
    def test_all_techniques_detected(self):
        for tech_name, tech in TECHNIQUES.items():
            det = InjectionDetector()
            result = None
            for syscall in tech["sequence"]:
                event = TelemetryEvent(source=EventSource.SYSCALL, raw_data={"pid": 100, "syscall": syscall, "process": "test"})
                result = det.detect(event)
            assert result is not None, f"Failed to detect {tech_name}"
            assert result.event_type == "process_injection"

    def test_no_false_positive_normal_usage(self):
        det = InjectionDetector()
        for syscall in ["read", "write", "open", "close", "stat", "mmap"]:
            event = TelemetryEvent(source=EventSource.SYSCALL, raw_data={"pid": 100, "syscall": syscall})
            result = det.detect(event)
        assert result is None
