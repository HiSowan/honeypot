"""Tests for the ML pipeline: preprocess, predict, and shadow_mode."""
import csv
import io
import tempfile
from pathlib import Path
from unittest.mock import MagicMock, patch

import numpy as np
import pandas as pd
import pytest

from ml.features import FEATURE_COLS, ATTACK_CATEGORIES
from ml.preprocess import load_unsw, build_features
from controller.log_parser import ConnRecord


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_unsw_df(n=10, attack_cat="Generic", proto="tcp", state="SF"):
    return pd.DataFrame({
        "dur":        [0.1] * n,
        "sbytes":     [100] * n,
        "dbytes":     [200] * n,
        "spkts":      [3] * n,
        "dpkts":      [4] * n,
        "proto":      [proto] * n,
        "state":      [state] * n,
        "attack_cat": [attack_cat] * n,
    })


def _make_rec(**kwargs):
    defaults = dict(
        ts=1000.0, uid="abc", src_ip="1.2.3.4", src_port=12345,
        dst_ip="10.0.0.1", dst_port=80, proto="tcp",
        duration=0.1, orig_bytes=100, resp_bytes=200,
        conn_state="SF", orig_pkts=3, resp_pkts=4,
    )
    defaults.update(kwargs)
    return ConnRecord(**defaults)


# ---------------------------------------------------------------------------
# preprocess
# ---------------------------------------------------------------------------

class TestBuildFeatures:
    def test_output_columns_match_feature_cols(self):
        df = _make_unsw_df()
        X, y = build_features(df)
        assert list(X.columns) == FEATURE_COLS

    def test_proto_one_hot(self):
        df = _make_unsw_df(proto="udp")
        X, _ = build_features(df)
        assert (X["proto_udp"] == 1).all()
        assert (X["proto_tcp"] == 0).all()

    def test_conn_state_one_hot(self):
        df = _make_unsw_df(state="REJ")
        X, _ = build_features(df)
        assert (X["conn_state_REJ"] == 1).all()
        assert (X["conn_state_SF"] == 0).all()

    def test_unknown_attack_cat_mapped_to_normal(self):
        df = _make_unsw_df(attack_cat="UnknownCategory")
        _, y = build_features(df)
        assert (y == "Normal").all()

    def test_nan_attack_cat_mapped_to_normal(self):
        df = _make_unsw_df()
        df["attack_cat"] = np.nan
        _, y = build_features(df)
        assert (y == "Normal").all()

    def test_known_categories_preserved(self):
        for cat in ["DoS", "Exploits", "Reconnaissance"]:
            df = _make_unsw_df(attack_cat=cat)
            _, y = build_features(df)
            assert (y == cat).all()


# ---------------------------------------------------------------------------
# predict
# ---------------------------------------------------------------------------

class TestPredictor:
    def _make_predictor(self, attack_type="Generic", is_anomaly=False, score=0.05):
        from ml.predict import Predictor, Prediction
        pred = Predictor.__new__(Predictor)
        rf = MagicMock()
        rf.predict.return_value = np.array([attack_type])
        iforest = MagicMock()
        iforest.decision_function.return_value = np.array([score])
        iforest.predict.return_value = np.array([-1 if is_anomaly else 1])
        pred._rf = rf
        pred._if = iforest
        return pred

    def test_returns_prediction_with_attack_type(self):
        predictor = self._make_predictor(attack_type="DoS")
        rec = _make_rec()
        result = predictor.predict(rec)
        assert result.attack_type == "DoS"

    def test_anomaly_flag_true_when_if_returns_minus_one(self):
        predictor = self._make_predictor(is_anomaly=True, score=-0.2)
        result = predictor.predict(_make_rec())
        assert result.is_anomaly is True
        assert result.anomaly_score == pytest.approx(-0.2)

    def test_anomaly_flag_false_when_normal(self):
        predictor = self._make_predictor(is_anomaly=False, score=0.1)
        result = predictor.predict(_make_rec())
        assert result.is_anomaly is False

    def test_none_fields_handled(self):
        predictor = self._make_predictor()
        rec = _make_rec(duration=None, orig_bytes=None, orig_pkts=None)
        result = predictor.predict(rec)
        assert result.attack_type is not None


# ---------------------------------------------------------------------------
# shadow_mode
# ---------------------------------------------------------------------------

class TestShadowMode:
    def _make_shadow(self, tmp_path, is_anomaly=True, score=-0.2):
        from ml.shadow_mode import ShadowMode
        mock_pred_obj = MagicMock()
        mock_pred_obj.is_anomaly = is_anomaly
        mock_pred_obj.anomaly_score = score
        mock_pred_obj.attack_type = "Reconnaissance"

        predictor = MagicMock()
        predictor.predict.return_value = mock_pred_obj

        log_path = tmp_path / "shadow_mode.csv"
        return ShadowMode(log_path=log_path, predictor=predictor), log_path

    def test_creates_csv_with_header(self, tmp_path):
        shadow, log_path = self._make_shadow(tmp_path)
        assert log_path.exists()
        with open(log_path) as f:
            header = f.readline()
        assert "would_block" in header

    def test_logs_row_per_evaluate_call(self, tmp_path):
        shadow, log_path = self._make_shadow(tmp_path)
        shadow.evaluate(_make_rec())
        shadow.evaluate(_make_rec(src_ip="5.6.7.8"))
        with open(log_path) as f:
            rows = f.readlines()
        assert len(rows) == 3  # header + 2 data rows

    def test_would_block_true_when_anomaly_below_threshold(self, tmp_path):
        shadow, log_path = self._make_shadow(tmp_path, is_anomaly=True, score=-0.5)
        shadow.evaluate(_make_rec(), block_threshold=-0.1)
        with open(log_path) as f:
            reader = csv.DictReader(f)
            row = next(reader)
        assert row["would_block"] == "True"

    def test_would_block_false_when_score_above_threshold(self, tmp_path):
        shadow, log_path = self._make_shadow(tmp_path, is_anomaly=True, score=0.05)
        shadow.evaluate(_make_rec(), block_threshold=-0.1)
        with open(log_path) as f:
            reader = csv.DictReader(f)
            row = next(reader)
        assert row["would_block"] == "False"

    def test_returns_none_when_no_predictor(self, tmp_path):
        from ml.shadow_mode import ShadowMode
        shadow = ShadowMode(log_path=tmp_path / "s.csv", predictor=None)
        result = shadow.evaluate(_make_rec())
        assert result is None
