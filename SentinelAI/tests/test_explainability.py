"""Tests for the explainability (SHAP) module."""

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


def test_global_importance_ranked(trained):
    df = generate_synthetic_flows(n_normal=100, n_attack=40, seed=42)
    explainer = Explainer(trained.model)
    ranked = explainer.global_importance(df[FEATURE_COLUMNS])
    assert len(ranked) == len(FEATURE_COLUMNS)
    assert all("feature" in r and "importance" in r for r in ranked)
    vals = [r["importance"] for r in ranked]
    assert vals == sorted(vals, reverse=True)
    assert vals[0] >= 0.0


def test_global_importance_features_valid(trained):
    df = generate_synthetic_flows(n_normal=100, n_attack=40, seed=42)
    explainer = Explainer(trained.model)
    ranked = explainer.global_importance(df[FEATURE_COLUMNS])
    features = {r["feature"] for r in ranked}
    assert features == set(FEATURE_COLUMNS)


def test_local_explanation_structure(trained):
    df = generate_synthetic_flows(n_normal=100, n_attack=40, seed=42)
    explainer = Explainer(trained.model)
    expl = explainer.local_explanation(df[FEATURE_COLUMNS], row_index=0)
    assert expl["prediction"] in (0, 1)
    assert expl["label_name"] in ("normal", "attack")
    assert "base_value" in expl
    assert "driving_attack" in expl
    assert "pushing_normal" in expl
    assert all("feature" in e and "shap" in e for e in expl["driving_attack"])


def test_explain_dataframe_adds_columns(trained):
    df = generate_synthetic_flows(n_normal=100, n_attack=40, seed=42)
    explainer = Explainer(trained.model)
    out = explainer.explain_dataframe(df[FEATURE_COLUMNS])
    assert "top_feature" in out.columns
    assert "top_shap" in out.columns
    assert len(out) == len(df)
    assert out["top_feature"].isin(FEATURE_COLUMNS).all()


def test_missing_shap_raises(monkeypatch):
    import src.explainability.explainer as mod

    model = object()
    monkeypatch.setattr(mod, "shap", None)
    with pytest.raises(ImportError):
        Explainer(model)
