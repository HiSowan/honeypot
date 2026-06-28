"""Extract per-source-IP features from Zeek conn records over a time window."""
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Iterable

from .log_parser import ConnRecord


@dataclass
class IPFeatures:
    ip: str
    conn_count: int = 0
    unique_dst_ports: set = field(default_factory=set)
    unique_dst_ips: set = field(default_factory=set)
    total_bytes_sent: int = 0
    total_bytes_recv: int = 0
    syn_scan_count: int = 0   # conn_state S0 = SYN with no reply
    protocols: set = field(default_factory=set)

    def to_dict(self) -> dict:
        return {
            "ip": self.ip,
            "conn_count": self.conn_count,
            "unique_dst_ports": len(self.unique_dst_ports),
            "unique_dst_ips": len(self.unique_dst_ips),
            "total_bytes_sent": self.total_bytes_sent,
            "total_bytes_recv": self.total_bytes_recv,
            "syn_scan_count": self.syn_scan_count,
            "unique_protocols": len(self.protocols),
        }


def extract_features(
    records: Iterable[ConnRecord],
    window_start: float,
    window_end: float,
) -> dict[str, IPFeatures]:
    """Return per-source-IP feature objects for records within [window_start, window_end)."""
    features: dict[str, IPFeatures] = defaultdict(lambda: IPFeatures(ip=""))

    for rec in records:
        if not (window_start <= rec.ts < window_end):
            continue
        if not rec.src_ip:
            continue

        f = features[rec.src_ip]
        f.ip = rec.src_ip
        f.conn_count += 1
        f.unique_dst_ports.add(rec.dst_port)
        f.unique_dst_ips.add(rec.dst_ip)
        f.total_bytes_sent += rec.orig_bytes or 0
        f.total_bytes_recv += rec.resp_bytes or 0
        if rec.conn_state == "S0":
            f.syn_scan_count += 1
        if rec.proto:
            f.protocols.add(rec.proto)

    return dict(features)
