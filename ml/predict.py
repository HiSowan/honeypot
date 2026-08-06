"""Inference wrapper — loads saved models and scores a single Zeek ConnRecord."""
import logging
from dataclasses import dataclass
from pathlib import Path

import joblib
import numpy as np

from .features import FEATURE_COLS

logger = logging.getLogger(__name__)

RF_MODEL_PATH = Path(__file__).parent / "models" / "rf_attack_type.joblib"
IF_MODEL_PATH = Path(__file__).parent / "models" / "iforest_anomaly.joblib"


@dataclass
class Prediction:
    attack_type: str        # RF classification result
    is_anomaly: bool        # Isolation Forest flag
    anomaly_score: float    # raw IF decision score (lower = more anomalous)


def _conn_to_vector(rec) -> np.ndarray:
    """Convert a ConnRecord to a feature vector matching FEATURE_COLS."""
    proto = (rec.proto or "").lower()
    state = (rec.conn_state or "").upper()
    row = {
        "duration":        rec.duration or 0.0,
        "orig_bytes":      rec.orig_bytes or 0,
        "resp_bytes":      rec.resp_bytes or 0,
        "orig_pkts":       rec.orig_pkts or 0,
        "resp_pkts":       rec.resp_pkts or 0,
        "proto_tcp":       int(proto == "tcp"),
        "proto_udp":       int(proto == "udp"),
        "proto_icmp":      int(proto == "icmp"),
        "conn_state_S0":   int(state == "S0"),
        "conn_state_SF":   int(state == "SF"),
        "conn_state_REJ":  int(state == "REJ"),
        "conn_state_RSTO": int(state == "RSTO"),
    }
    return np.array([row[f] for f in FEATURE_COLS], dtype=float).reshape(1, -1)


class Predictor:
    def __init__(
        self,
        rf_path: Path = RF_MODEL_PATH,
        if_path: Path = IF_MODEL_PATH,
    ) -> None:
        self._rf = joblib.load(rf_path)
        self._if = joblib.load(if_path)
        logger.info("Models loaded: RF=%s, IF=%s", rf_path.name, if_path.name)

    def predict(self, rec) -> Prediction:
        vec = _conn_to_vector(rec)
        attack_type = self._rf.predict(vec)[0]
        score = float(self._if.decision_function(vec)[0])
        is_anomaly = self._if.predict(vec)[0] == -1
        return Prediction(attack_type=attack_type, is_anomaly=is_anomaly, anomaly_score=score)
