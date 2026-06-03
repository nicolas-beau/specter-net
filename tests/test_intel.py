"""Tests for threat intelligence."""
import pytest
from specter_net.intel.ioc_database import IOCDatabase

class TestIOCDatabase:
    def test_insert_and_lookup(self):
        db = IOCDatabase(":memory:")
        db.insert("ip", "10.0.0.1", 0.9, "test")
        result = db.lookup("10.0.0.1")
        assert result is not None
        assert result["type"] == "ip"

    def test_lookup_missing(self):
        db = IOCDatabase(":memory:")
        assert db.lookup("not.exist") is None
