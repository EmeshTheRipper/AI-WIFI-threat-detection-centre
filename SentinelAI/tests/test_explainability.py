"""Tests for the explainability (SHAP) module."""

import pandas as pd
import pytest

from src.explainability import Explainer
from src.ml.dataset import generate_synthetic_flows
from src.ml.trainer import FEATURE_COLUMNS, ModelTrainer


@pytest.fixture
def trained():
    df = generate_synthetic_flows(n_normal=100, n_attack=40, seed=42)
    trainer = ModelTrainer()
    trainer.train(df)
    return trainer


def _feature_frame() -> pd.DataFrame:
    df = generate_synthetic_flows(n_normal=100, n_attack=40, seed=42)
    X = df[FEATURE_COLUMNS]
    assert isinstance(X, pd.DataFrame)
    return X


def test_global_importance_ranked(trained):
    X = _feature_frame()
    explainer = Explainer(trained.model)
    ranked = explainer.global_importance(X)
    assert len(ranked) == len(FEATURE_COLUMNS)
    assert all("feature" in r and "importance" in r for r in ranked)
    vals = [r["importance"] for r in ranked]
    assert vals == sorted(vals, reverse=True)
    assert vals[0] >= 0.0


def test_global_importance_features_valid(trained):
    X = _feature_frame()
    explainer = Explainer(trained.model)
    ranked = explainer.global_importance(X)
    features = {r["feature"] for r in ranked}
    assert features == set(FEATURE_COLUMNS)


def test_local_explanation_structure(trained):
    X = _feature_frame()
    explainer = Explainer(trained.model)
    expl = explainer.local_explanation(X, row_index=0)
    assert expl["prediction"] in (0, 1)
    assert expl["label_name"] in ("normal", "attack")
    assert "base_value" in expl
    assert "driving_attack" in expl
    assert "pushing_normal" in expl
    assert all("feature" in e and "shap" in e for e in expl["driving_attack"])
    assert isinstance(expl["reason"], str)


def test_explain_dataframe_adds_columns(trained):
    X = _feature_frame()
    explainer = Explainer(trained.model)
    out = explainer.explain_dataframe(X)
    assert "top_feature" in out.columns
    assert "top_shap" in out.columns
    assert "reason" in out.columns
    assert len(out) == len(X)
    top = out["top_feature"]
    assert isinstance(top, pd.Series)
    assert bool(top.isin(FEATURE_COLUMNS).all())


def test_missing_shap_raises(monkeypatch):
    import src.explainability.explainer as mod

    model = object()
    monkeypatch.setattr(mod, "shap", None)
    with pytest.raises(ImportError):
        Explainer(model)
