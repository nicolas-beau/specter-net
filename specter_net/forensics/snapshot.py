"""Forensic snapshot for compromised processes."""
import os, json, time, hashlib, logging
from pathlib import Path

logger = logging.getLogger("specter-net.forensics")

class ForensicSnapshot:
    def __init__(self, output_dir="/var/lib/specter-net/forensics"):
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)

    def capture(self, pid: int, reason: str) -> str:
        sid = f"snap_{pid}_{int(time.time())}"
        d = self.output_dir / sid
        d.mkdir(exist_ok=True)
        data = {"snapshot_id": sid, "pid": pid, "reason": reason, "timestamp": time.time()}
        with open(d / "metadata.json", "w") as f: json.dump(data, f, indent=2)
        logger.info(f"Snapshot captured: {sid}")
        return str(d)
