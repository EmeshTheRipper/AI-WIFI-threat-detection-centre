"""Tests for the ML training and prediction module."""

import numpy as np
import pandas as pd

from src.ml.dataset import generate_synthetic_flows
from src.ml.predictor import ModelPredictor
from src.ml.trainer import FEATURE_COLUMNS, ModelTrainer


def test_synthetic_dataset_shape():
    df = generate_synthetic_flows(n_normal=50, n_attack=20, seed=99)
    assert len(df) == 70
    assert "label" in df.columns
    assert df["label"].value_counts().to_dict() == {0: 50, 1: 20}


def test_synthetic_dataset_has_features():
    df = generate_synthetic_flows(n_normal=10, n_attack=5, seed=1)
    for col in FEATURE_COLUMNS:
        assert col in df.columns, f"Missing feature column: {col}"


def test_trainer_prepare_data():
    df = generate_synthetic_flows(n_normal=20, n_attack=10, seed=7)
    trainer = ModelTrainer()
    X, y = trainer.prepare_data(df)
    assert isinstance(X, pd.DataFrame)
    assert isinstance(y, pd.Series)
    assert len(X) == 30
    assert set(y.unique()) == {0, 1}


def test_trainer_train_produces_metrics():
    df = generate_synthetic_flows(n_normal=100, n_attack=40, seed=42)
    trainer = ModelTrainer(test_size=0.25)
    metrics = trainer.train(df)
    assert "accuracy" in metrics
    assert "precision" in metrics
    assert "recall" in metrics
    assert "f1" in metrics
    assert "confusion_matrix" in metrics
    assert 0.0 <= metrics["accuracy"] <= 1.0
    assert metrics["train_size"] + metrics["test_size"] == 140


def test_trainer_predict():
    df = generate_synthetic_flows(n_normal=80, n_attack=30, seed=10)
    trainer = ModelTrainer()
    trainer.train(df)
    preds = trainer.predict(df)
    assert len(preds) == len(df)
    assert set(np.unique(preds)).issubset({0, 1})


def test_trainer_save_and_load(tmp_path):
    df = generate_synthetic_flows(n_normal=60, n_attack=20, seed=55)
    trainer = ModelTrainer()
    trainer.train(df)
    model_path = str(tmp_path / "test_model.joblib")
    trainer.save(model_path, metadata={"accuracy": 0.95})
    loaded = ModelTrainer.load(model_path)
    preds_orig = trainer.predict(df)
    preds_loaded = loaded.predict(df)
    np.testing.assert_array_equal(preds_orig, preds_loaded)


def test_predictor_classify(tmp_path):
    df = generate_synthetic_flows(n_normal=80, n_attack=30, seed=22)
    trainer = ModelTrainer()
    trainer.train(df)
    model_path = str(tmp_path / "predictor_test.joblib")
    trainer.save(model_path)
    predictor = ModelPredictor.from_model(model_path)
    result = predictor.classify(df)
    assert "prediction" in result.columns
    assert "confidence" in result.columns
    assert "label_name" in result.columns
    assert set(result["label_name"].unique()) <= {"normal", "attack"}


def test_predictor_summary():
    df = generate_synthetic_flows(n_normal=50, n_attack=20, seed=33)
    trainer = ModelTrainer()
    trainer.train(df)
    predictor = ModelPredictor(trainer)
    result = predictor.classify(df)
    summary = predictor.summary(result)
    assert summary["total"] == 70
    assert "counts" in summary
    assert "avg_confidence" in summary
