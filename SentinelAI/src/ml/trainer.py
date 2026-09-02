"""Model training and evaluation for the ML detection pipeline."""

import json
import logging
from pathlib import Path

import joblib
import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import (
    accuracy_score,
    classification_report,
    confusion_matrix,
    f1_score,
    precision_score,
    recall_score,
)
from sklearn.model_selection import train_test_split

logger = logging.getLogger(__name__)

FEATURE_COLUMNS = [
    "src_port", "dst_port", "packets", "total_bytes",
    "min_size", "max_size", "mean_size", "std_size",
    "total_payload", "mean_payload", "syn_packets", "rst_packets",
    "proto_TCP", "proto_UDP",
]


class ModelTrainer:
    def __init__(self, model=None, test_size: float = 0.2, random_state: int = 42):
        self.model = model or RandomForestClassifier(
            n_estimators=100,
            max_depth=10,
            random_state=random_state,
        )
        self.test_size = test_size
        self.random_state = random_state
        self._feature_columns: list[str] | None = None

    def prepare_data(
        self, df: pd.DataFrame, label_col: str = "label"
    ) -> tuple[pd.DataFrame, pd.Series]:
        available = [c for c in FEATURE_COLUMNS if c in df.columns]
        if not available:
            raise ValueError("No recognized feature columns found in DataFrame")
        self._feature_columns = available
        X = df[available].copy()
        y = df[label_col].copy()
        return X, y

    def train(self, df: pd.DataFrame, label_col: str = "label") -> dict:
        X, y = self.prepare_data(df, label_col)
        X_train, X_test, y_train, y_test = train_test_split(
            X, y,
            test_size=self.test_size,
            random_state=self.random_state,
            stratify=y,
        )
        logger.info("Train split: %d, Test split: %d", len(X_train), len(X_test))

        self.model.fit(X_train, y_train)
        y_pred = self.model.predict(X_test)

        metrics = self._compute_metrics(y_test, y_pred)
        metrics["train_size"] = len(X_train)
        metrics["test_size"] = len(X_test)
        metrics["feature_columns"] = self._feature_columns

        logger.info("Training complete — accuracy=%.2f, f1=%.2f", metrics["accuracy"], metrics["f1"])
        return metrics

    def predict(self, df: pd.DataFrame) -> np.ndarray:
        X = self._get_features(df)
        return self.model.predict(X)

    def predict_proba(self, df: pd.DataFrame) -> np.ndarray:
        X = self._get_features(df)
        return self.model.predict_proba(X)

    def _get_features(self, df: pd.DataFrame) -> pd.DataFrame:
        if self._feature_columns is not None:
            available = [c for c in self._feature_columns if c in df.columns]
        else:
            available = [c for c in FEATURE_COLUMNS if c in df.columns]
        if not available:
            raise ValueError("No recognized feature columns found in DataFrame")
        self._feature_columns = available
        return df[available].copy()

    def save(self, model_path: str, metadata: dict | None = None):
        path = Path(model_path)
        path.parent.mkdir(parents=True, exist_ok=True)
        joblib.dump(self.model, path)
        if metadata:
            meta_path = path.with_suffix(".json")
            meta_path.write_text(json.dumps(metadata, indent=2))
        logger.info("Model saved to %s", path)

    @classmethod
    def load(cls, model_path: str) -> "ModelTrainer":
        model = joblib.load(model_path)
        trainer = cls(model=model)
        logger.info("Model loaded from %s", model_path)
        return trainer

    def _compute_metrics(self, y_true, y_pred) -> dict:
        return {
            "accuracy": round(accuracy_score(y_true, y_pred), 4),
            "precision": round(precision_score(y_true, y_pred, zero_division=0), 4),
            "recall": round(recall_score(y_true, y_pred, zero_division=0), 4),
            "f1": round(f1_score(y_true, y_pred, zero_division=0), 4),
            "confusion_matrix": confusion_matrix(y_true, y_pred).tolist(),
            "classification_report": classification_report(
                y_true, y_pred, target_names=["normal", "attack"], output_dict=True
            ),
        }
