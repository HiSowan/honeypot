"""Train an Isolation Forest on UNSW-NB15 for anomaly detection."""
import argparse
import logging
from pathlib import Path

import joblib
from sklearn.ensemble import IsolationForest

from .preprocess import load_unsw, build_features

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s: %(message)s")
logger = logging.getLogger(__name__)

MODEL_PATH = Path(__file__).parent / "models" / "iforest_anomaly.joblib"

# contamination: expected fraction of anomalies in training data
CONTAMINATION = 0.1


def train(csv_path: Path, model_out: Path = MODEL_PATH) -> None:
    logger.info("Loading dataset: %s", csv_path)
    df = load_unsw(csv_path)
    X, _ = build_features(df)
    logger.info("Dataset: %d rows, %d features", len(X), X.shape[1])

    logger.info("Training Isolation Forest (contamination=%.2f)...", CONTAMINATION)
    clf = IsolationForest(n_estimators=100, contamination=CONTAMINATION,
                          n_jobs=-1, random_state=42)
    clf.fit(X)

    model_out.parent.mkdir(parents=True, exist_ok=True)
    joblib.dump(clf, model_out)
    logger.info("Model saved to %s", model_out)

    scores = clf.decision_function(X)
    anomalies = (clf.predict(X) == -1).sum()
    logger.info("Anomalies flagged on training set: %d / %d (%.1f%%)",
                anomalies, len(X), 100 * anomalies / len(X))


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("csv", type=Path, help="Path to UNSW-NB15 training CSV")
    parser.add_argument("--out", type=Path, default=MODEL_PATH)
    args = parser.parse_args()
    train(args.csv, args.out)
