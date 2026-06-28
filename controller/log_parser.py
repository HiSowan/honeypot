"""Parse Zeek TSV log files from disk."""
from dataclasses import dataclass
from pathlib import Path
from typing import Iterator


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


def parse_conn_log(path: Path) -> Iterator[ConnRecord]:
    """Yield ConnRecord objects from a Zeek conn.log file."""
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
                continue

            parts = line.split("\t")
            row = dict(zip(fields, parts))

            yield ConnRecord(
                ts=float(row.get("ts", 0)),
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
