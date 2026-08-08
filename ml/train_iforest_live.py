"""Retrain Isolation Forest on real captured Zeek conn.log data.

Uses the same feature vector as inference (FEATURE_COLS) so the retrained
model is a drop-in replacement for the UNSW-NB15 trained one.

Usage:
    python -m ml.train_iforest_live <conn.log> [<conn.log> ...]
    python -m ml.train_iforest_live /opt/zeek/logs/current/conn.log
"""
import argparse
import logging
from pathlib import Path

import joblib
import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest

from controller.log_parser import parse_conn_log
from ml.predict import _conn_to_vector
from ml.features import FEATURE_COLS

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s: %(message)s")
logger = logging.getLogger(__name__)

MODEL_OUT = Path(__file__).parent / "models" / "iforest_live.joblib"
CONTAMINATION = 0.1


def build_matrix(log_paths: list[Path]) -> pd.DataFrame:
    rows = []
    for path in log_paths:
        if not path.exists():
            logger.warning("Skipping missing file: %s", path)
            continue
        logger.info("Parsing %s ...", path)
        for rec in parse_conn_log(path):
            rows.append(_conn_to_vector(rec).iloc[0])
    if not rows:
        raise RuntimeError("No records found in provided log files.")
    df = pd.DataFrame(rows, columns=FEATURE_COLS)
    logger.info("Total records: %d", len(df))
    return df


def train(log_paths: list[Path], model_out: Path = MODEL_OUT) -> None:
    X = build_matrix(log_paths)

    logger.info("Training Isolation Forest on live data (contamination=%.2f)...", CONTAMINATION)
    clf = IsolationForest(n_estimators=100, contamination=CONTAMINATION,
                          n_jobs=-1, random_state=42)
    clf.fit(X)

    model_out.parent.mkdir(parents=True, exist_ok=True)
    joblib.dump(clf, model_out)
    logger.info("Model saved to %s", model_out)

    anomalies = (clf.predict(X) == -1).sum()
    logger.info("Anomalies flagged on training set: %d / %d (%.1f%%)",
                anomalies, len(X), 100 * anomalies / len(X))


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("logs", nargs="+", type=Path, help="Zeek conn.log file(s)")
    parser.add_argument("--out", type=Path, default=MODEL_OUT)
    args = parser.parse_args()
    train(args.logs, args.out)
