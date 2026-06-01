"""Alerting engine."""
import logging, time
from typing import List, Callable
from dataclasses import dataclass
from .events import ThreatEvent, Severity

logger = logging.getLogger("specter-net.alerting")

@dataclass
class AlertRule:
    name: str
    severity: Severity
    cooldown: int
    last_fired: float = 0

class AlertEngine:
    def __init__(self):
        self.rules: List[AlertRule] = [
            AlertRule("critical-flood", Severity.CRITICAL, 300),
            AlertRule("injection-burst", Severity.CRITICAL, 120),
            AlertRule("c2-detected", Severity.CRITICAL, 60),
        ]
        self.handlers: List[Callable] = []
        self.alert_history: List[dict] = []

    def add_handler(self, h: Callable):
        self.handlers.append(h)

    def evaluate(self, event: ThreatEvent):
        now = time.time()
        for rule in self.rules:
            if now - rule.last_fired < rule.cooldown: continue
            if event.severity == rule.severity:
                rule.last_fired = now
                alert = {"rule": rule.name, "event": event.to_dict(), "timestamp": now}
                self.alert_history.append(alert)
                for h in self.handlers: h(alert)

    def get_alerts(self, limit=50):
        return self.alert_history[-limit:]
