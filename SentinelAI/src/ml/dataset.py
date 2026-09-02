"""Synthetic dataset generation and CSV loading for ML training.

Generates labeled flow records that mimic normal and attack traffic
patterns, allowing the ML pipeline to be tested without real captured data.
"""

import logging

import numpy as np
import pandas as pd

logger = logging.getLogger(__name__)

LABEL_NORMAL = 0
LABEL_ATTACK = 1


def generate_synthetic_flows(
    n_normal: int = 200,
    n_attack: int = 50,
    seed: int = 42,
) -> pd.DataFrame:
    rng = np.random.default_rng(seed)
    rows = []

    for _ in range(n_normal):
        proto = rng.choice(["TCP", "UDP"], p=[0.8, 0.2])
        dst_port = int(rng.choice([80, 443, 53, 8080, 22]))
        rows.append({
            "src_port": int(rng.integers(1024, 65535)),
            "dst_port": dst_port,
            "packets": int(rng.integers(5, 100)),
            "total_bytes": int(rng.integers(500, 50000)),
            "min_size": int(rng.integers(40, 100)),
            "max_size": int(rng.integers(500, 1500)),
            "mean_size": round(float(rng.uniform(200, 800)), 2),
            "std_size": round(float(rng.uniform(10, 200)), 2),
            "total_payload": int(rng.integers(200, 40000)),
            "mean_payload": round(float(rng.uniform(100, 600)), 2),
            "syn_packets": int(rng.integers(0, 3)),
            "rst_packets": int(rng.integers(0, 2)),
            "proto_TCP": 1 if proto == "TCP" else 0,
            "proto_UDP": 1 if proto == "UDP" else 0,
            "label": LABEL_NORMAL,
        })

    for _ in range(n_attack):
        attack_type = rng.choice(["port_scan", "syn_flood", "ping_sweep"])
        if attack_type == "port_scan":
            rows.append(_make_port_scan_flow(rng))
        elif attack_type == "syn_flood":
            rows.append(_make_syn_flood_flow(rng))
        else:
            rows.append(_make_ping_sweep_flow(rng))

    df = pd.DataFrame(rows)
    logger.info(
        "Generated synthetic dataset: %d normal + %d attack = %d total",
        n_normal, n_attack, len(df),
    )
    return df


def _make_port_scan_flow(rng) -> dict:
    return {
        "src_port": int(rng.integers(1024, 65535)),
        "dst_port": int(rng.integers(1, 1024)),
        "packets": int(rng.integers(1, 4)),
        "total_bytes": int(rng.integers(60, 300)),
        "min_size": 40,
        "max_size": 60,
        "mean_size": 50.0,
        "std_size": 5.0,
        "total_payload": 0,
        "mean_payload": 0.0,
        "syn_packets": int(rng.integers(1, 4)),
        "rst_packets": 0,
        "proto_TCP": 1,
        "proto_UDP": 0,
        "label": LABEL_ATTACK,
    }


def _make_syn_flood_flow(rng) -> dict:
    n = int(rng.integers(30, 200))
    return {
        "src_port": int(rng.integers(1024, 65535)),
        "dst_port": int(rng.choice([80, 443, 22])),
        "packets": n,
        "total_bytes": n * 60,
        "min_size": 40,
        "max_size": 60,
        "mean_size": 54.0,
        "std_size": 8.0,
        "total_payload": 0,
        "mean_payload": 0.0,
        "syn_packets": n,
        "rst_packets": 0,
        "proto_TCP": 1,
        "proto_UDP": 0,
        "label": LABEL_ATTACK,
    }


def _make_ping_sweep_flow(rng) -> dict:
    return {
        "src_port": 0,
        "dst_port": 0,
        "packets": int(rng.integers(1, 5)),
        "total_bytes": int(rng.integers(28, 120)),
        "min_size": 28,
        "max_size": 28,
        "mean_size": 28.0,
        "std_size": 0.0,
        "total_payload": 0,
        "mean_payload": 0.0,
        "syn_packets": 0,
        "rst_packets": 0,
        "proto_TCP": 0,
        "proto_UDP": 0,
        "label": LABEL_ATTACK,
    }


def load_csv_dataset(path: str) -> pd.DataFrame:
    df = pd.read_csv(path)
    if "label" not in df.columns:
        raise ValueError(f"Dataset at {path} must contain a 'label' column")
    logger.info("Loaded CSV dataset: %d rows from %s", len(df), path)
    return df


def label_encoded_features(
    features: pd.DataFrame,
    labels: dict | pd.Series | list | int,
) -> pd.DataFrame:
    """Attach a label column to an encoded features DataFrame for training.

    ``labels`` may be:
    - a dict/Series mapping a key column (e.g. 'src_ip:dst_ip:dst_port') to 0/1
    - a list/array of labels with the same length as ``features``
    - a single int (0/1) applied to every row

    Returns a copy of ``features`` with the ``label`` column present, dropping
    any non-numeric identifier columns so it is ready for ``ModelTrainer``.
    """
    result = features.copy()
    id_cols = [c for c in ["src_ip", "dst_ip"] if c in result.columns]

    if isinstance(labels, dict):
        key = None
        for candidate in ["flow_key", "key"]:
            if candidate in result.columns:
                key = candidate
                break
        if key is None and id_cols:
            key = "__flow_key__"
            result[key] = (
                result["src_ip"].astype(str) + ":" +
                result["dst_ip"].astype(str) + ":" +
                result["dst_port"].astype(str)
            )
        if key is None:
            raise ValueError("labels dict requires a key column (flow_key) or src/dst IP columns")
        result["label"] = result[key].map(labels)
        if result["label"].isna().any():
            raise ValueError("Some rows have no matching label in the provided mapping")
        if key != "__flow_key__":
            result = result.drop(columns=[key])
    elif isinstance(labels, (list, pd.Series, np.ndarray)):
        result["label"] = list(labels)
        if len(result["label"]) != len(result):
            raise ValueError("labels list length must match number of rows")
    else:
        result["label"] = int(labels)

    # Drop identifier columns that are not part of the feature vectors.
    for col in id_cols:
        if col in result.columns:
            result = result.drop(columns=[col])

    result["label"] = result["label"].astype(int)
    return result
