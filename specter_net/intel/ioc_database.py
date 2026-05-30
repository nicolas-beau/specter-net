"""IOC database with SQLite backend."""
import sqlite3, json, time, logging
from typing import Optional, Dict, List
from pathlib import Path

logger = logging.getLogger("specter-net.ioc_db")

class IOCDatabase:
    def __init__(self, db_path: str = "data/iocs.db"):
        self.db_path = Path(db_path)
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._init_db()

    def _init_db(self):
        with sqlite3.connect(str(self.db_path)) as conn:
            conn.execute("CREATE TABLE IF NOT EXISTS iocs (id INTEGER PRIMARY KEY, ioc_type TEXT, value TEXT UNIQUE, confidence REAL, source TEXT, first_seen REAL, last_seen REAL, tags TEXT)")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_value ON iocs(value)")

    def insert(self, ioc_type: str, value: str, confidence: float, source: str, tags: list = None):
        with sqlite3.connect(str(self.db_path)) as conn:
            conn.execute("INSERT OR REPLACE INTO iocs (ioc_type,value,confidence,source,first_seen,last_seen,tags) VALUES (?,?,?,?,?,?,?)", (ioc_type, value, confidence, source, time.time(), time.time(), json.dumps(tags or [])))

    def lookup(self, value: str) -> Optional[Dict]:
        with sqlite3.connect(str(self.db_path)) as conn:
            row = conn.execute("SELECT * FROM iocs WHERE value=?", (value,)).fetchone()
            if row: return {"id": row[0], "type": row[1], "value": row[2], "confidence": row[3]}
        return None

    def count(self) -> int:
        with sqlite3.connect(str(self.db_path)) as conn:
            return conn.execute("SELECT COUNT(*) FROM iocs").fetchone()[0]
