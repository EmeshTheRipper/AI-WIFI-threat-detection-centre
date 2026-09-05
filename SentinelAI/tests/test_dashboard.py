"""Tests for the dashboard data pipeline."""

import pandas as pd

from src.dashboard import analyze, level_distribution, to_summary_frame

SAMPLE = "data/samples/level2_sample.pcap"


def test_analyze_returns_result():
    result = analyze(SAMPLE)
    assert result.packets == 61
    assert result.flows == 61
    assert len(result.scored) > 0
    assert "by_verdict" in result.summary


def test_summary_frame_columns():
    result = analyze(SAMPLE)
    df = to_summary_frame(result)
    for col in ["src_ip", "risk_score", "risk_level", "events", "targets", "tactics", "techniques"]:
        assert col in df.columns
    assert df["risk_score"].max() >= df["risk_score"].min()


def test_summary_frame_sorted_descending():
    result = analyze(SAMPLE)
    df = to_summary_frame(result)
    scores = df["risk_score"].tolist()
    assert scores == sorted(scores, reverse=True)


def test_level_distribution_shape():
    result = analyze(SAMPLE)
    df = level_distribution(result)
    assert {"risk_level", "count"} <= set(df.columns)
    counts = df["count"]
    total = int(counts.sum()) if isinstance(counts, pd.Series) else 0
    assert total == len(result.scored)
