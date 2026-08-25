"""Honeypot controller entry point — supports Static, Adaptive, and Adaptive+ML phases."""
import logging
import os
import time
from pathlib import Path

from .allowlist import load_allowlist, is_allowlisted
from .feature_extractor import extract_features, IPFeatures
from .firewall import Firewall
from .log_parser import parse_conn_log
from .phase_manager import read_phase, ports_for_phase

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(name)s: %(message)s",
)
logger = logging.getLogger(__name__)

POLL_INTERVAL = 60
FEATURE_WINDOW = 300

SCAN_PORT_THRESHOLD = 5
SYN_SCAN_THRESHOLD = 10
ML_BLOCK_THRESHOLD = -0.1

# Cowrie's internal listener ports — never modified by rotation
_COWRIE_SSH_PORT = 2222
_COWRIE_TEL_PORT = 2223

# External port pools for Cowrie PREROUTING rotation.
# On each new-scanner detection the external port advances one step so that the
# well-known port (22 / 23) appears closed to any follow-up scan.
_SSH_EXT_POOL = [22, 2022, 5022]
_TEL_EXT_POOL = [23, 2023, 5023]


def _find_conn_log(zeek_log_dir: Path) -> Path | None:
    candidate = zeek_log_dir / "conn.log"
    if candidate.exists():
        return candidate
    return None


def _is_scanner(f: IPFeatures) -> bool:
    return (
        len(f.unique_dst_ports) >= SCAN_PORT_THRESHOLD
        or f.syn_scan_count >= SYN_SCAN_THRESHOLD
    )


def _adaptive_rotate(f: IPFeatures, allowed_ports: list[dict], fw: Firewall) -> None:
    probed = f.unique_dst_ports
    for entry in allowed_ports:
        port = entry["port"]
        proto = entry.get("protocol", "tcp")
        if port in probed:
            logger.info("Adaptive: closing probed port %d/%s due to scanner %s", port, proto, f.ip)
            fw.close_port(port, proto)
        else:
            fw.open_port(port, proto)


def _rotate_cowrie_ports(
    ssh_ext: int, tel_ext: int, fw: Firewall
) -> tuple[int, int]:
    """Advance Cowrie's external PREROUTING ports one step in each pool.

    Removes the current PREROUTING REDIRECT rules for ssh_ext/tel_ext and
    adds new rules for the next entries in _SSH_EXT_POOL / _TEL_EXT_POOL.
    The Cowrie listeners (_COWRIE_SSH_PORT, _COWRIE_TEL_PORT) are never touched.
    Returns the new (ssh_ext, tel_ext).
    """
    ssh_next = _SSH_EXT_POOL[(_SSH_EXT_POOL.index(ssh_ext) + 1) % len(_SSH_EXT_POOL)]
    tel_next = _TEL_EXT_POOL[(_TEL_EXT_POOL.index(tel_ext) + 1) % len(_TEL_EXT_POOL)]

    fw.del_prerouting_redirect(ssh_ext, _COWRIE_SSH_PORT)
    fw.add_prerouting_redirect(ssh_next, _COWRIE_SSH_PORT)
    fw.del_prerouting_redirect(tel_ext, _COWRIE_TEL_PORT)
    fw.add_prerouting_redirect(tel_next, _COWRIE_TEL_PORT)

    logger.info(
        "Cowrie PREROUTING rotated — SSH :%d→:%d  Telnet :%d→:%d",
        ssh_ext, ssh_next, tel_ext, tel_next,
    )
    return ssh_next, tel_next


def _load_ml():
    """Lazy-load ML predictor and shadow mode logger. Returns (None, None) if models missing."""
    try:
        from ml.predict import Predictor
        from ml.shadow_mode import ShadowMode
        predictor = Predictor()
        shadow = ShadowMode(predictor=predictor)
        logger.info("ML pipeline loaded (shadow mode active)")
        return predictor, shadow
    except FileNotFoundError as e:
        logger.warning("ML models not found — Phase 3 ML disabled: %s", e)
        return None, None


def run(zeek_log_dir: Path, dry_run: bool = True) -> None:
    """Main controller loop. Runs until interrupted.

    dry_run=True (default) means firewall calls are logged but never executed.
    Set dry_run=False only when intentionally applying live firewall rules.
    ML blocking also requires ML_LIVE=1 env var; without it, flagged IPs are only logged.
    """
    allowlist = load_allowlist()
    fw = Firewall(dry_run=dry_run)
    ml_live = os.environ.get("ML_LIVE", "0") == "1"
    logger.info("Operator allow-list loaded: %d entr(ies)", len(allowlist))
    logger.info("Firewall dry_run=%s | ML_LIVE=%s", dry_run, ml_live)

    predictor = None
    shadow = None

    # Track current Cowrie external ports and which scanner IPs have already
    # triggered a PREROUTING rotation (avoid re-rotating on every tick).
    cowrie_ssh_ext = 22
    cowrie_tel_ext = 23
    seen_scanners: set[str] = set()

    while True:
        phase = read_phase()
        allowed_ports = ports_for_phase(phase)
        logger.info("Phase: %s | Permitted ports: %s", phase, [p["port"] for p in allowed_ports])

        if phase == "adaptive_ml" and predictor is None:
            predictor, shadow = _load_ml()

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
        window_records = [r for r in records if window_start <= r.ts <= now]

        # Phase 3: score every connection through the ML shadow pipeline
        ml_flagged: set[str] = set()
        if phase == "adaptive_ml" and shadow is not None:
            for rec in window_records:
                if is_allowlisted(rec.src_ip, allowlist):
                    continue
                pred = shadow.evaluate(rec, block_threshold=ML_BLOCK_THRESHOLD)
                if pred is not None and pred.is_anomaly and pred.anomaly_score < ML_BLOCK_THRESHOLD:
                    ml_flagged.add(rec.src_ip)

        for ip, f in features.items():
            if is_allowlisted(ip, allowlist):
                logger.debug("Skipping allow-listed IP %s", ip)
                continue

            logger.info(
                "IP %-16s | conns=%d ports=%d syn_scans=%d bytes_sent=%d",
                ip, f.conn_count, len(f.unique_dst_ports), f.syn_scan_count, f.total_bytes_sent,
            )

            if phase in ("adaptive", "adaptive_ml") and _is_scanner(f):
                logger.info("Scanner detected: %s — rotating ports", ip)
                _adaptive_rotate(f, allowed_ports, fw)
                if ip not in seen_scanners:
                    cowrie_ssh_ext, cowrie_tel_ext = _rotate_cowrie_ports(
                        cowrie_ssh_ext, cowrie_tel_ext, fw
                    )
                    seen_scanners.add(ip)

            if phase == "adaptive_ml" and ip in ml_flagged:
                if ml_live:
                    logger.info("ML: blocking %s (live)", ip)
                    fw.block_ip(ip)
                else:
                    logger.info(
                        "ML: would block %s (shadow — set ML_LIVE=1 to enable live blocking)", ip
                    )

        logger.info("Tick complete — %d IPs in window, sleeping %ds", len(features), POLL_INTERVAL)
        time.sleep(POLL_INTERVAL)


if __name__ == "__main__":
    zeek_dir = Path(os.environ.get("ZEEK_LOG_DIR", "/opt/zeek/logs/current"))
    live = os.environ.get("FIREWALL_LIVE", "0") == "1"
    run(zeek_dir, dry_run=not live)
