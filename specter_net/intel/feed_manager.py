"""Manage threat intelligence feeds."""
import logging, time
from typing import List, Dict, Optional
from dataclasses import dataclass

logger = logging.getLogger("specter-net.intel")

@dataclass
class IOC:
    ioc_type: str
    value: str
    confidence: float
    source: str
    first_seen: float
    last_seen: float
    tags: list

class FeedManager:
    def __init__(self):
        self.feeds: Dict[str, dict] = {}
        self.iocs: List[IOC] = []

    def add_feed(self, name: str, url: str):
        self.feeds[name] = {"url": url, "last_update": 0}

    def check_ioc(self, ioc_type: str, value: str) -> Optional[IOC]:
        for ioc in self.iocs:
            if ioc.ioc_type == ioc_type and ioc.value == value:
                return ioc
        return None

    def add_ioc(self, ioc: IOC):
        self.iocs.append(ioc)
