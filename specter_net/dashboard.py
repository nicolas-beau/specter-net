"""Dashboard data API for real-time visualization."""
import time
from typing import List
from collections import Counter

class DashboardAPI:
    def __init__(self, pipeline, alert_engine):
        self.pipeline = pipeline
        self.alert_engine = alert_engine
        self.threat_history: List[dict] = []

    def get_overview(self):
        return {"events": self.pipeline.stats["processed"], "threats": self.pipeline.stats["threats"], "alerts": len(self.alert_engine.get_alerts())}

    def get_top_threats(self, limit=10):
        types = Counter(t.get("event_type", "unknown") for t in self.threat_history)
        return [{"type": k, "count": v} for k, v in types.most_common(limit)]

    def record_threat(self, event: dict):
        self.threat_history.append(event)
        if len(self.threat_history) > 10000:
            self.threat_history = self.threat_history[-5000:]
