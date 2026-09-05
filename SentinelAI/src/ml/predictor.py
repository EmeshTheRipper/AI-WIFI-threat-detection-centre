"""Prediction interface for trained ML models."""

import logging

import numpy as np
import pandas as pd

from .trainer import ModelTrainer

logger = logging.getLogger(__name__)


class ModelPredictor:
    def __init__(self, trainer: ModelTrainer):
        self.trainer = trainer

    @classmethod
    def from_model(cls, model_path: str) -> "ModelPredictor":
        trainer = ModelTrainer.load(model_path)
        return cls(trainer)

    def classify(self, df: pd.DataFrame) -> pd.DataFrame:
        predictions = self.trainer.predict(df)
        probas = self.trainer.predict_proba(df)

        result = df.copy()
        result["prediction"] = predictions
        result["confidence"] = probas.max(axis=1)
        result["label_name"] = np.where(predictions == 0, "normal", "attack")

        n_attack = int((predictions == 1).sum())
        n_normal = int((predictions == 0).sum())
        logger.info(
            "Classification complete: %d normal, %d attack out of %d flows",
            n_normal, n_attack, len(predictions),
        )
        return result

    def summary(self, classified_df: pd.DataFrame) -> dict:
        counts = classified_df["label_name"].value_counts().to_dict()
        conf = classified_df["confidence"]
        avg_conf = conf.mean() if isinstance(conf, pd.Series) else 0.0
        return {
            "total": len(classified_df),
            "counts": counts,
            "avg_confidence": round(float(avg_conf), 4),
        }
