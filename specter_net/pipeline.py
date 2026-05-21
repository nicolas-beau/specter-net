"""Event pipeline — stream processing and correlation."""
import logging
import time
import threading
from typing import List, Callable, Optional, Dict
from queue import Queue, Empty
from .events import TelemetryEvent, ThreatEvent, Severity

logger = logging.getLogger("specter-net.pipeline")

class EventPipeline:
    """Process telemetry events through detection stages."""

    def __init__(self, max_queue_size: int = 10000):
        self.queue: Queue = Queue(maxsize=max_queue_size)
        self.detectors: List[Callable] = []
        self.outputs: List[Callable] = []
        self.correlation_window: Dict[str, List[TelemetryEvent]] = {}
        self._running = False
        self._worker: Optional[threading.Thread] = None
        self.stats = {"processed": 0, "threats": 0, "dropped": 0}

    def add_detector(self, detector: Callable):
        """Add a detection stage to the pipeline."""
        self.detectors.append(detector)

    def add_output(self, output: Callable):
        """Add an output sink (e.g., phantom-veil, cerebro)."""
        self.outputs.append(output)

    def ingest(self, event: TelemetryEvent):
        """Ingest a telemetry event into the pipeline."""
        try:
            self.queue.put_nowait(event)
        except:
            self.stats["dropped"] += 1

    def start(self):
        """Start the pipeline worker thread."""
        self._running = True
        self._worker = threading.Thread(target=self._process_loop, daemon=True)
        self._worker.start()
        logger.info("Event pipeline started")

    def stop(self):
        self._running = False
        if self._worker:
            self._worker.join(timeout=5)
        logger.info("Event pipeline stopped")

    def _process_loop(self):
        """Main processing loop."""
        while self._running:
            try:
                event = self.queue.get(timeout=0.1)
                self._process_event(event)
                self.stats["processed"] += 1
            except Empty:
                continue

    def _process_event(self, event: TelemetryEvent):
        """Run event through all detectors."""
        for detector in self.detectors:
            result = detector(event)
            if result and isinstance(result, ThreatEvent):
                self.stats["threats"] += 1
                self._correlate(result)
                for output in self.outputs:
                    output(result)

    def _correlate(self, event: ThreatEvent):
        """Correlate threat events within time window."""
        key = f"{event.event_type}:{event.target_pid}"
        self.correlation_window.setdefault(key, []).append(event)

        # Check for repeated events (higher confidence)
        recent = [e for e in self.correlation_window[key] if time.time() - e.timestamp < 300]
        if len(recent) >= 3:
            logger.warning(f"Repeated threat pattern: {key} ({len(recent)} events in 5min)")

    def get_stats(self) -> dict:
        return self.stats.copy()
