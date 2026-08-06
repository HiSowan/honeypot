"""Model evaluation utilities."""
import logging
import pandas as pd
from sklearn.metrics import classification_report, confusion_matrix

logger = logging.getLogger(__name__)


def print_report(model, X_test, y_test, model_name: str = "Model") -> None:
    y_pred = model.predict(X_test)
    logger.info("\n=== %s Evaluation ===\n%s", model_name,
                classification_report(y_test, y_pred, zero_division=0))

    cm = confusion_matrix(y_test, y_pred, labels=model.classes_)
    cm_df = pd.DataFrame(cm, index=model.classes_, columns=model.classes_)
    logger.info("Confusion matrix:\n%s", cm_df.to_string())
