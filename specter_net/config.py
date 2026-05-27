"""Configuration for specter-net."""
import os
import yaml
import logging
from typing import Dict, Any

logger = logging.getLogger("specter-net.config")

DEFAULT_CONFIG = {
    "specter-net": {
        "mode": "enforce",
        "log_level": "info",
        "event_buffer_size": 10000,
        "correlation_window": 300,
    },
    "monitors": {
        "syscall": {"enabled": True, "eBPF": True},
        "network": {"enabled": True, "interface": "eth0", "promiscuous": True},
        "memory": {"enabled": True, "scan_interval": 60},
    },
    "detectors": {
        "injection": {"enabled": True, "min_confidence": 0.70},
        "lateral_movement": {"enabled": True, "min_confidence": 0.75},
        "c2_beacon": {"enabled": True, "min_samples": 8, "max_jitter": 0.20},
        "exfiltration": {"enabled": True, "large_transfer_mb": 50},
    },
    "outputs": {
        "phantom_veil": {"enabled": True, "endpoint": "localhost:9090"},
        "cerebro": {"enabled": True, "endpoint": "localhost:9091"},
        "obsidian_core": {"enabled": True, "endpoint": "localhost:8443"},
    },
}

class Config:
    def __init__(self, path: str = None):
        self.path = path or os.environ.get("SPECTER_CONFIG", "config/specter-net.yaml")
        self.data = DEFAULT_CONFIG.copy()

    def load(self) -> dict:
        if os.path.exists(self.path):
            with open(self.path) as f:
                user = yaml.safe_load(f) or {}
            self._merge(self.data, user)
        return self.data

    def get(self, key: str, default=None):
        keys = key.split(".")
        v = self.data
        for k in keys:
            if isinstance(v, dict) and k in v:
                v = v[k]
            else:
                return default
        return v

    def _merge(self, base, override):
        for k, v in override.items():
            if k in base and isinstance(base[k], dict) and isinstance(v, dict):
                self._merge(base[k], v)
            else:
                base[k] = v
