"""Model explainability using SHAP.

Provides global feature-importance rankings and per-prediction local
explanations (which features drove a flow toward the attack class).
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
    def __init__(self, model):
        if shap is None:
            raise ImportError("shap is required for explainability. Install with: pip install shap")
        self.model = model

    def _tree_explainer(self):
        return shap.TreeExplainer(self.model)

    def global_importance(self, X: pd.DataFrame) -> list[dict]:
        """Return a ranked list of features by mean |SHAP| importance."""
        explainer = self._tree_explainer()
        shap_values = explainer.shap_values(X)

        if isinstance(shap_values, list):
            # Multi-class: use the attack class (last) for importance
            base_vals = shap_values[-1]
        else:
            base_vals = shap_values

        if base_vals.ndim == 3:
            base_vals = base_vals[..., -1]

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
        """Explain a single prediction: top features pushing toward each class."""
        explainer = self._tree_explainer()
        vals = explainer.shap_values(X)

        if isinstance(vals, list):
            attack_vals = vals[-1]
        else:
            attack_vals = vals
        if attack_vals.ndim == 3:
            attack_vals = attack_vals[..., -1]

        sample = attack_vals[row_index]
        value = float(self.model.predict(X.iloc[[row_index]])[0])

        positive = []
        negative = []
        for i, name in enumerate(X.columns):
            entry = {"feature": name, "value": float(X.iloc[row_index][name]), "shap": round(float(sample[i]), 4)}
            if sample[i] >= 0:
                positive.append(entry)
            else:
                negative.append(entry)

        positive.sort(key=lambda e: -e["shap"])
        negative.sort(key=lambda e: e["shap"])

        exp = explainer.expected_value
        if isinstance(exp, (list, tuple, np.ndarray)):
            if isinstance(exp, np.ndarray) and exp.ndim == 0:
                base = float(exp)
            else:
                base = float(np.mean([float(x) for x in exp]))
        else:
            base = float(exp)

        return {
            "prediction": int(value),
            "label_name": "attack" if value == 1 else "normal",
            "base_value": round(base, 4),
            "driving_attack": positive[:5],
            "pushing_normal": negative[:5],
        }

    def explain_dataframe(self, df: pd.DataFrame) -> pd.DataFrame:
        """Add a human-readable top-contributing-feature column to a copy of df."""
        result = df.copy()
        result["top_feature"] = ""
        result["top_shap"] = 0.0
        explainer = self._tree_explainer()
        vals = explainer.shap_values(df)
        if isinstance(vals, list):
            attack_vals = vals[-1]
        else:
            attack_vals = vals
        if attack_vals.ndim == 3:
            attack_vals = attack_vals[..., -1]

        for i in range(len(df)):
            row_shap = attack_vals[i]
            idx = int(np.argmax(np.abs(row_shap)))
            result.loc[result.index[i], "top_feature"] = df.columns[idx]
            result.loc[result.index[i], "top_shap"] = round(float(row_shap[idx]), 4)
        return result
