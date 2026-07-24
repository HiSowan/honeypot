"""Honeypot controller entry point — Phase 1 static loop."""
import logging
import time
from pathlib import Path

from .allowlist import load_allowlist, is_allowlisted
from .feature_extractor import extract_features
from .log_parser import parse_conn_log
from .phase_manager import read_phase, ports_for_phase

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(name)s: %(message)s",
)
logger = logging.getLogger(__name__)

# How often the loop runs (seconds)
POLL_INTERVAL = 60

# Feature window size (seconds) — look back this far on each tick
FEATURE_WINDOW = 300


def _find_conn_log(zeek_log_dir: Path) -> Path | None:
    candidate = zeek_log_dir / "conn.log"
    if candidate.exists():
        return candidate
    return None


def run(zeek_log_dir: Path) -> None:
    """Main controller loop. Runs until interrupted."""
    allowlist = load_allowlist()
    logger.info("Operator allow-list loaded: %d entr(ies)", len(allowlist))

    while True:
        phase = read_phase()
        ports = ports_for_phase(phase)
        logger.info("Phase: %s | Permitted ports: %s", phase, [p["port"] for p in ports])

        conn_log = _find_conn_log(zeek_log_dir)
        if conn_log is None:
            logger.warning("No conn.log found in %s — is Zeek running?", zeek_log_dir)
            time.sleep(POLL_INTERVAL)
            continue

        now = time.time()
        window_start = now - FEATURE_WINDOW

        try:
            records = list(parse_conn_log(conn_log))
        except OSError as e:
            logger.error("Could not read conn.log: %s", e)
            time.sleep(POLL_INTERVAL)
            continue

        features = extract_features(records, window_start, now)

        for ip, f in features.items():
            if is_allowlisted(ip, allowlist):
                logger.debug("Skipping allow-listed IP %s", ip)
                continue
            logger.info("IP %-16s | conns=%d ports=%d syn_scans=%d bytes_sent=%d",
                        ip,
                        f.conn_count,
                        len(f.unique_dst_ports),
                        f.syn_scan_count,
                        f.total_bytes_sent)

        logger.info("Tick complete — %d IPs in window, sleeping %ds", len(features), POLL_INTERVAL)
        time.sleep(POLL_INTERVAL)


if __name__ == "__main__":
    import os
    zeek_dir = Path(os.environ.get("ZEEK_LOG_DIR", "/opt/zeek/logs/current"))
    run(zeek_dir)
