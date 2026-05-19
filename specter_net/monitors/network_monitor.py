"""Network traffic monitoring and anomaly detection."""
import logging
import time
import math
from typing import Dict, List, Optional, Callable, Tuple
from dataclasses import dataclass, field
from collections import defaultdict

logger = logging.getLogger("specter-net.network")

@dataclass
class NetworkFlow:
    src_ip: str
    dst_ip: str
    src_port: int
    dst_port: int
    protocol: str
    bytes_sent: int
    bytes_recv: int
    packets: int
    start_time: float
    last_seen: float
    dns_queries: List[str] = field(default_factory=list)

@dataclass
class DNSQuery:
    query: str
    qtype: str  # A, AAAA, TXT, CNAME
    response: str
    timestamp: float
    pid: int

class NetworkMonitor:
    """Network traffic analysis for C2, tunneling, and exfiltration detection."""

    # Known C2 beacon intervals (seconds)
    BEACON_INTERVALS = [1.0, 5.0, 10.0, 30.0, 60.0, 300.0, 900.0]

    def __init__(self, callback: Optional[Callable] = None):
        self.callback = callback
        self.flows: Dict[str, NetworkFlow] = {}
        self.dns_queries: List[DNSQuery] = []
        self.beacon_candidates: Dict[str, List[float]] = defaultdict(list)
        self._running = False

    def start(self):
        self._running = True
        logger.info("Network monitor started")

    def stop(self):
        self._running = False
        logger.info("Network monitor stopped")

    def on_flow(self, flow: NetworkFlow):
        """Process a network flow."""
        flow_key = f"{flow.src_ip}:{flow.dst_ip}:{flow.dst_port}"
        self.flows[flow_key] = flow

        # Check for beacon patterns
        self.beacon_candidates[flow.dst_ip].append(flow.last_seen)
        self._check_beacon(flow.dst_ip)

        # Check for data exfiltration
        self._check_exfiltration(flow)

    def on_dns_query(self, query: DNSQuery):
        """Process a DNS query."""
        self.dns_queries.append(query)
        self._check_dns_tunneling(query)

    def _check_beacon(self, dst_ip: str):
        """Detect C2 beacon patterns via timing analysis."""
        times = self.beacon_candidates[dst_ip]
        if len(times) < 5:
            return

        # Calculate intervals between connections
        intervals = [times[i+1] - times[i] for i in range(len(times)-4, len(times)-1)]
        if not intervals:
            return

        # Check for regularity (low jitter = suspicious)
        avg = sum(intervals) / len(intervals)
        if avg < 0.1:
            return
        jitter = math.sqrt(sum((x - avg) ** 2 for x in intervals) / len(intervals)) / avg

        if jitter < 0.15 and avg > 0.5:  # Regular beacon
            logger.warning(f"C2 beacon detected: {dst_ip} (interval={avg:.1f}s, jitter={jitter:.3f})")

    def _check_dns_tunneling(self, query: DNSQuery):
        """Detect DNS tunneling via query analysis."""
        # Long subdomain labels are suspicious
        parts = query.query.split(".")
        for part in parts[:-1]:  # Skip TLD
            if len(part) > 52:  # Max normal label is 63, suspicious above 52
                logger.warning(f"DNS tunneling suspected: {query.query[:60]}... (label_len={len(part)})")
                return True

        # High entropy in subdomains
        for part in parts[:-1]:
            if len(part) > 10:
                entropy = self._shannon_entropy(part)
                if entropy > 4.0:
                    logger.warning(f"DNS tunneling suspected: high entropy ({entropy:.2f}) in {query.query}")
                    return True
        return False

    def _check_exfiltration(self, flow: NetworkFlow):
        """Detect potential data exfiltration."""
        # Large outbound transfer to external IP
        if flow.bytes_sent > 100 * 1024 * 1024:  # > 100MB outbound
            if not self._is_internal_ip(flow.dst_ip):
                logger.warning(f"Large outbound transfer: {flow.src_ip} -> {flow.dst_ip} ({flow.bytes_sent / 1024 / 1024:.1f}MB)")

    def _shannon_entropy(self, data: str) -> float:
        if not data:
            return 0.0
        freq = defaultdict(int)
        for c in data:
            freq[c] += 1
        length = len(data)
        return -sum((count/length) * math.log2(count/length) for count in freq.values())

    def _is_internal_ip(self, ip: str) -> bool:
        return ip.startswith(("10.", "172.16.", "192.168.", "127."))
