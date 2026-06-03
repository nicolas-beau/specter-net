"""Tests for alerting."""
import pytest
from specter_net.alerting import AlertEngine
from specter_net.events import ThreatEvent, Severity

class TestAlertEngine:
    def test_critical_triggers_alert(self):
        engine = AlertEngine()
        alerts = []
        engine.add_handler(lambda a: alerts.append(a))
        engine.evaluate(ThreatEvent(event_type="test", severity=Severity.CRITICAL, confidence=0.99))
        assert len(alerts) > 0
