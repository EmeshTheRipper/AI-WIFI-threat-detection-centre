"""Tests for real-labeled dataset enrichment."""

import pandas as pd
import pytest

from src.ml.dataset import generate_synthetic_flows, label_encoded_features
from src.ml.trainer import FEATURE_COLUMNS, ModelTrainer


@pytest.fixture
def encoded_frame():
    df = generate_synthetic_flows(n_normal=5, n_attack=3, seed=3)
    df["src_ip"] = "192.168.1.10"
    df["dst_ip"] = "10.0.0.1"
    df["dst_port"] = [80, 443, 53, 8080, 22, 1, 80, 22]
    # Strip label so it acts like raw features to be labeled
    df = df.drop(columns=["label"])
    return df


def test_label_scalar_applies_to_all(encoded_frame):
    out = label_encoded_features(encoded_frame, 1)
    assert list(out["label"]) == [1] * len(encoded_frame)
    assert "src_ip" not in out.columns


def test_label_from_list(encoded_frame):
    labels = [0, 0, 0, 0, 0, 1, 1, 1]
    out = label_encoded_features(encoded_frame, labels)
    assert list(out["label"]) == labels


def test_label_from_dict_by_ips(encoded_frame):
    mapping = {}
    for _, row in encoded_frame.iterrows():
        key = f"{row['src_ip']}:{row['dst_ip']}:{row['dst_port']}"
        mapping[key] = 1
    out = label_encoded_features(encoded_frame, mapping)
    assert list(out["label"]) == [1] * len(encoded_frame)


def test_labeled_features_trainable(encoded_frame):
    labels = [0, 0, 0, 0, 0, 1, 1, 1]
    out = label_encoded_features(encoded_frame, labels)
    trainer = ModelTrainer()
    metrics = trainer.train(out, label_col="label")
    assert "accuracy" in metrics


def test_mismatched_list_raises(encoded_frame):
    with pytest.raises(ValueError):
        label_encoded_features(encoded_frame, [0, 1])
