"""Shadow mode — logs what the ML pipeline WOULD block without taking action.

Enable shadow mode before live blocking to analyse false positives.
"""
import csv
import logging
from datetime import datetime, timezone
from pathlib import Path

from .predict import Predictor, Prediction

logger = logging.getLogger(__name__)

DEFAULT_LOG = Path("/var/log/honeypot/shadow_mode.csv")


class ShadowMode:
    def __init__(self, log_path: Path = DEFAULT_LOG, predictor: Predictor | None = None) -> None:
        log_path.parent.mkdir(parents=True, exist_ok=True)
        self._path = log_path
        self._predictor = predictor
        self._ensure_header()

    def _ensure_header(self) -> None:
        if not self._path.exists():
            with open(self._path, "w", newline="") as f:
                w = csv.writer(f)
                w.writerow([
                    "timestamp", "src_ip", "dst_port", "proto",
                    "attack_type", "is_anomaly", "anomaly_score", "would_block",
                ])

    def evaluate(self, rec, block_threshold: float = -0.1) -> Prediction | None:
        """Score a ConnRecord and log what would happen. Returns None if no predictor loaded."""
        if self._predictor is None:
            return None

        pred = self._predictor.predict(rec)
        would_block = pred.is_anomaly and pred.anomaly_score < block_threshold

        with open(self._path, "a", newline="") as f:
            w = csv.writer(f)
            w.writerow([
                datetime.now(timezone.utc).isoformat(),
                rec.src_ip,
                rec.dst_port,
                rec.proto,
                pred.attack_type,
                pred.is_anomaly,
                round(pred.anomaly_score, 4),
                would_block,
            ])

        if would_block:
            logger.info(
                "[SHADOW] would block %s — attack_type=%s anomaly_score=%.4f",
                rec.src_ip, pred.attack_type, pred.anomaly_score,
            )

        return pred
