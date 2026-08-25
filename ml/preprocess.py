"""Load and preprocess UNSW-NB15 CSV files into model-ready DataFrames."""
import pandas as pd
from pathlib import Path
from .features import UNSW_COL_MAP, UNSW_LABEL_COL, FEATURE_COLS, ATTACK_CATEGORIES

# UNSW-NB15 uses Argus connection-state vocabulary (FIN, CON, INT, REQ, RST, CLO).
# Our FEATURE_COLS use Zeek vocabulary (S0, SF, REJ, RSTO).
# Without this map all four conn_state_ columns are 0 for every training record,
# because no UNSW-NB15 record has a state value of S0, SF, REJ, or RSTO.
_UNSW_STATE_TO_ZEEK: dict[str, str] = {
    "REQ": "S0",    # connection request, no reply → SYN sent, no SYN-ACK
    "FIN": "SF",    # cleanly terminated via FIN → established + cleanly closed
    "CON": "SF",    # established / ongoing → closest Zeek equivalent
    "CLO": "SF",    # closed connection
    "RST": "RSTO",  # reset by either side
    # INT (active/interrupted) has no clean Zeek mapping; leaves all columns 0
}


def load_unsw(csv_path: Path) -> pd.DataFrame:
    """Load a UNSW-NB15 CSV and return a cleaned DataFrame."""
    df = pd.read_csv(csv_path, low_memory=False)
    df.columns = df.columns.str.strip().str.lower()
    return df


def build_features(df: pd.DataFrame) -> tuple[pd.DataFrame, pd.Series]:
    """Return (X, y) where X has FEATURE_COLS and y has attack category labels."""
    # Rename UNSW columns to our internal names
    df = df.rename(columns=UNSW_COL_MAP)

    # Translate UNSW-NB15 Argus state vocabulary to Zeek vocabulary so that
    # conn_state_ one-hot features carry the same semantics at train and inference time.
    df["conn_state"] = df["conn_state"].str.upper().map(_UNSW_STATE_TO_ZEEK).fillna("")

    # One-hot encode protocol
    for proto in ("tcp", "udp", "icmp"):
        df[f"proto_{proto}"] = (df["proto"].str.lower() == proto).astype(int)

    # One-hot encode connection state (Zeek vocabulary, now consistent with training data)
    for state in ("S0", "SF", "REJ", "RSTO"):
        df[f"conn_state_{state}"] = (df["conn_state"].str.upper() == state).astype(int)

    # Fill missing numeric values with 0
    X = df[FEATURE_COLS].fillna(0).astype(float)

    # Label: attack category; treat empty/NaN as "Normal"
    y = df[UNSW_LABEL_COL].fillna("Normal").str.strip()
    y = y.where(y.isin(ATTACK_CATEGORIES), other="Normal")

    return X, y
