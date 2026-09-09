"""Parse Zeek TSV log files from disk."""
import logging
from ipaddress import ip_address
from dataclasses import dataclass, field
from math import isfinite
from pathlib import Path
from typing import Iterator


logger = logging.getLogger(__name__)


@dataclass
class ParseStats:
    """Per-read diagnostics; callers can supply one without changing iteration."""
    yielded: int = 0
    skipped: int = 0
    reasons: dict[str, int] = field(default_factory=dict)

    def reject(self, reason: str) -> None:
        self.skipped += 1
        self.reasons[reason] = self.reasons.get(reason, 0) + 1


@dataclass
class ConnRecord:
    ts: float
    uid: str
    src_ip: str
    src_port: int
    dst_ip: str
    dst_port: int
    proto: str
    duration: float | None
    orig_bytes: int | None
    resp_bytes: int | None
    conn_state: str
    orig_pkts: int | None
    resp_pkts: int | None


def _cast(value: str, typ):
    """Return typ(value) or None if value is the Zeek unset sentinel '-'."""
    if value == "-":
        return None
    try:
        return typ(value)
    except (ValueError, TypeError):
        return None


def parse_conn_log(path: Path, stats: ParseStats | None = None) -> Iterator[ConnRecord]:
    """Yield records, skipping malformed rows and invalid timestamps."""
    if stats is None:
        stats = ParseStats()
    fields: list[str] | None = None

    with open(path) as f:
        for line in f:
            line = line.rstrip("\n")

            if line.startswith("#fields"):
                fields = line.split("\t")[1:]
                continue
            if line.startswith("#"):
                continue
            if fields is None:
                stats.reject("missing_header")
                continue

            parts = line.split("\t")
            if len(parts) != len(fields):
                stats.reject("column_count")
                continue
            row = dict(zip(fields, parts))
            ts = _cast(row.get("ts", "-"), float)
            if ts is None or not isfinite(ts):
                stats.reject("timestamp")
                continue
            try:
                ip_address(row.get("id.orig_h", ""))
                ip_address(row.get("id.resp_h", ""))
            except ValueError:
                stats.reject("ip_address")
                continue

            stats.yielded += 1
            yield ConnRecord(
                ts=ts,
                uid=row.get("uid", ""),
                src_ip=row.get("id.orig_h", ""),
                src_port=_cast(row.get("id.orig_p", "-"), int) or 0,
                dst_ip=row.get("id.resp_h", ""),
                dst_port=_cast(row.get("id.resp_p", "-"), int) or 0,
                proto=row.get("proto", ""),
                duration=_cast(row.get("duration", "-"), float),
                orig_bytes=_cast(row.get("orig_bytes", "-"), int),
                resp_bytes=_cast(row.get("resp_bytes", "-"), int),
                conn_state=row.get("conn_state", ""),
                orig_pkts=_cast(row.get("orig_pkts", "-"), int),
                resp_pkts=_cast(row.get("resp_pkts", "-"), int),
            )

    if stats.skipped:
        logger.warning("Skipped %d malformed conn.log rows: %s", stats.skipped, stats.reasons)
