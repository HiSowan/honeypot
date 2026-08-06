"""Train a Random Forest classifier on UNSW-NB15 to classify attack type."""
import argparse
import logging
from pathlib import Path

import joblib
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split

from .preprocess import load_unsw, build_features
from .evaluate import print_report

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s: %(message)s")
logger = logging.getLogger(__name__)

MODEL_PATH = Path(__file__).parent / "models" / "rf_attack_type.joblib"


def train(csv_path: Path, model_out: Path = MODEL_PATH) -> None:
    logger.info("Loading dataset: %s", csv_path)
    df = load_unsw(csv_path)
    X, y = build_features(df)
    logger.info("Dataset: %d rows, %d features, %d classes", len(X), X.shape[1], y.nunique())

    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=42, stratify=y
    )

    logger.info("Training Random Forest...")
    clf = RandomForestClassifier(n_estimators=100, n_jobs=-1, random_state=42)
    clf.fit(X_train, y_train)

    model_out.parent.mkdir(parents=True, exist_ok=True)
    joblib.dump(clf, model_out)
    logger.info("Model saved to %s", model_out)

    print_report(clf, X_test, y_test, model_name="RandomForest")


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("csv", type=Path, help="Path to UNSW-NB15 training CSV")
    parser.add_argument("--out", type=Path, default=MODEL_PATH)
    args = parser.parse_args()
    train(args.csv, args.out)
