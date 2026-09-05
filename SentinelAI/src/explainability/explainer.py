"""Model explainability using SHAP.

Provides global feature-importance rankings and per-prediction local
explanations (which features drove a flow toward the attack class). The
``reason`` output converts the raw SHAP attributions into a
human-readable alert justification suitable for SOC reporting.
"""

import logging

import numpy as np
import pandas as pd

logger = logging.getLogger(__name__)

try:
    import shap
except ImportError:  # pragma: no cover
    shap = None


class Explainer:
    """SHAP-backed explanations for a trained binary classifier.

    The model is expected to be a tree ensemble (RandomForest) trained with
    the features declared in ``src.ml.trainer.FEATURE_COLUMNS``.
    """

    def __init__(self, model):
        if shap is None:
            raise ImportError(
                "shap is required for explainability. Install with: pip install shap"
            )
        self.model = model

    def _tree_explainer(self):
        if shap is None:  # pragma: no cover - guarded in __init__
            raise RuntimeError("shap is not installed")
        return shap.TreeExplainer(self.model)

    @staticmethod
    def _attack_attributions(vals) -> np.ndarray:
        """Reduce the raw SHAP output to the attack-class attribution array.

        SHAP returns a list (one element per class) or a 3-D array for
        multi-output models; both are collapsed to the attack class.
        """
        if isinstance(vals, list):
            attack_vals = vals[-1]
        else:
            attack_vals = vals
        if attack_vals.ndim == 3:
            attack_vals = attack_vals[..., -1]
        return np.asarray(attack_vals)

    @staticmethod
    def _base_value(exp) -> float:
        """Extract the attack-class base value from a SHAP explainer."""
        if exp is None:
            return 0.0
        if isinstance(exp, (list, tuple, np.ndarray)):
            if isinstance(exp, np.ndarray) and exp.ndim == 0:
                return float(exp)
            return float(exp[-1])
        return float(exp)

    def global_importance(self, X: pd.DataFrame) -> list[dict]:
        """Return a ranked list of features by mean |SHAP| importance."""
        explainer = self._tree_explainer()
        shap_values = explainer.shap_values(X)
        base_vals = self._attack_attributions(shap_values)

        importances = np.abs(base_vals).mean(axis=0)
        ordered = np.argsort(importances)[::-1]

        ranked = []
        for idx in ordered:
            ranked.append({
                "feature": X.columns[idx],
                "importance": round(float(importances[idx]), 4),
            })
        return ranked

    def local_explanation(self, X: pd.DataFrame, row_index: int = 0) -> dict:
        """Explain a single prediction with a human-readable reason.

        Args:
            X: Feature DataFrame (encoded, model-ready columns).
            row_index: Row to explain.

        Returns:
            dict with prediction, base value, top driving features, and a
            ``reason`` string that summarizes *why* the model flagged the flow.
        """
        explainer = self._tree_explainer()
        attack_vals = self._attack_attributions(explainer.shap_values(X))
        sample = attack_vals[row_index]
        value = int(self.model.predict(X.iloc[[row_index]])[0])

        positive = []
        negative = []
        for i, name in enumerate(X.columns):
            entry = {
                "feature": name,
                "value": float(X.iloc[row_index][name]),
                "shap": round(float(sample[i]), 4),
            }
            if sample[i] >= 0:
                positive.append(entry)
            else:
                negative.append(entry)

        positive.sort(key=lambda e: -e["shap"])
        negative.sort(key=lambda e: e["shap"])

        exp = explainer.expected_value
        base = self._base_value(exp)

        return {
            "prediction": value,
            "label_name": "attack" if value == 1 else "normal",
            "base_value": round(base, 4),
            "driving_attack": positive[:5],
            "pushing_normal": negative[:5],
            "reason": self.natural_language_reason(
                X, row_index, _shap=np.asarray(sample)
            ),
        }

    def natural_language_reason(
        self, X: pd.DataFrame, row_index: int = 0, _shap: np.ndarray | None = None
    ) -> str:
        """Return a plain-English justification for a flow's prediction.

        The reason cites the top features pushing the instance toward the
        attack class, which both explains the model decision and gives SOC
        analysts a pointer for triage.
        """
        explainer = self._tree_explainer()
        shap_row = (
            self._attack_attributions(explainer.shap_values(X))[row_index]
            if _shap is None
            else _shap
        )

        value = int(self.model.predict(X.iloc[[row_index]])[0])
        base = self._base_value(explainer.expected_value)

        positive = []
        negative = []
        for i, name in enumerate(X.columns):
            entry = {
                "feature": name,
                "value": float(X.iloc[row_index][name]),
                "shap": float(shap_row[i]),
            }
            if shap_row[i] >= 0:
                positive.append(entry)
            else:
                negative.append(entry)
        positive.sort(key=lambda e: -e["shap"])
        negative.sort(key=lambda e: e["shap"])

        if value != 1:
            return (
                "Flow classified as normal: no feature shifted the model "
                "meaningfully toward the attack class."
            )

        drivers = " ".join(
            f"({d['feature']}={d['value']}, +{abs(d['shap']):.0%})"
            for d in positive[:3]
        )
        restrainers = " ".join(f"({n['feature']})" for n in negative[:2])
        reason = (
            f"Flow ranked attack (baseline atk-prob {base:.0%}). "
            f"Top inducers: {drivers}."
        )
        if restrainers:
            reason += f" Restraining: {restrainers}."
        return reason

    def explain_dataframe(self, df: pd.DataFrame) -> pd.DataFrame:
        """Add human-readable top-contributing-feature columns to a copy of df."""
        result = df.copy()
        result["top_feature"] = ""
        result["top_shap"] = 0.0
        result["reason"] = ""
        explainer = self._tree_explainer()
        attack_vals = self._attack_attributions(explainer.shap_values(df))

        for i in range(len(df)):
            row_shap = attack_vals[i]
            idx = int(np.argmax(np.abs(row_shap)))
            result.loc[result.index[i], "top_feature"] = df.columns[idx]
            result.loc[result.index[i], "top_shap"] = round(float(row_shap[idx]), 4)
            result.loc[result.index[i], "reason"] = self.natural_language_reason(
                df, i, _shap=np.asarray(row_shap)
            )
        return result