"""Tests for event system."""
import time
import pytest
from specter_net.events import ThreatEvent, TelemetryEvent, Severity, EventSource

class TestThreatEvent:
    def test_create(self):
        e = ThreatEvent(event_type="test", severity=Severity.HIGH, confidence=0.9)
        assert e.severity == Severity.HIGH
        assert e.confidence == 0.9

    def test_to_dict(self):
        e = ThreatEvent(event_type="injection", severity=Severity.CRITICAL)
        d = e.to_dict()
        assert d["severity"] == "critical"
        assert "event_id" in d

    def test_to_phantom_veil_event(self):
        e = ThreatEvent(event_type="test", source="specter-net", target_pid=1234)
        pv = e.to_phantom_veil_event()
        assert pv["source"] == "specter-net"
        assert pv["target_pid"] == 1234
