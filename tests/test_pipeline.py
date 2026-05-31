"""Tests for event pipeline."""
import time
import pytest
from specter_net.pipeline import EventPipeline
from specter_net.events import TelemetryEvent, EventSource

class TestEventPipeline:
    def setup_method(self):
        self.pipeline = EventPipeline()

    def test_ingest(self):
        event = TelemetryEvent(source=EventSource.SYSCALL, event_type="test")
        self.pipeline.ingest(event)
        assert self.pipeline.stats["dropped"] == 0

    def test_detector_registration(self):
        called = []
        self.pipeline.add_detector(lambda e: called.append(e) or None)
        assert len(self.pipeline.detectors) == 1

    def test_output_registration(self):
        self.pipeline.add_output(lambda e: None)
        assert len(self.pipeline.outputs) == 1
