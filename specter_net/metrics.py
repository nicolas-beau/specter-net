"""Prometheus metrics."""
from typing import Dict

class MetricsCollector:
    def __init__(self):
        self.counters: Dict[str, int] = {}
        self.gauges: Dict[str, float] = {}

    def inc(self, name: str, v: int = 1):
        self.counters[name] = self.counters.get(name, 0) + v
    def gauge(self, name: str, v: float):
        self.gauges[name] = v
    def export_prometheus(self) -> str:
        lines = [f"specter_net_{k} {v}" for k, v in self.counters.items()]
        lines += [f"specter_net_{k} {v}" for k, v in self.gauges.items()]
        return "\n".join(lines) + "\n"

metrics = MetricsCollector()
