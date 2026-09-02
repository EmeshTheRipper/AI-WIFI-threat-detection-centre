"""Build pandas DataFrames of features for model consumption.

Packets -> flows -> rows. Converts categorical fields (protocol, ports)
into forms ML models can use, and enforces numeric dtypes.
"""

import logging

import pandas as pd

logger = logging.getLogger(__name__)

NUMERIC_FLOW_FIELDS = [
    "src_port",
    "dst_port",
    "packets",
    "total_bytes",
    "min_size",
    "max_size",
    "mean_size",
    "std_size",
    "total_payload",
    "mean_payload",
    "syn_packets",
    "rst_packets",
]

CATEGORICAL_FLOW_FIELDS = [
    "protocol",
]


def flows_to_dataframe(flows: list[dict]) -> pd.DataFrame:
    """Convert a list of flow dicts into a numeric-feature DataFrame."""
    df = pd.DataFrame(flows)

    for field in NUMERIC_FLOW_FIELDS:
        if field in df.columns:
            df[field] = pd.to_numeric(df[field], errors="coerce").fillna(0)

    if "protocol" in df.columns:
        df["protocol"] = df["protocol"].astype("category")

    logger.info("Built DataFrame with %d rows x %d cols", *df.shape)
    return df


def encode_features(df: pd.DataFrame, drop_ips: bool = True) -> pd.DataFrame:
    """Encode categorical features for ML.

    Args:
        df: DataFrame from flows_to_dataframe.
        drop_ips: Drop raw IP address strings (nearly unique, not useful
            predictors on their own).

    Returns:
        A DataFrame with protocols one-hot encoded.
    """
    encoded = df.copy()

    if "protocol" in encoded.columns:
        encoded = pd.get_dummies(
            encoded, columns=["protocol"], prefix="proto", dtype=int
        )

    if drop_ips:
        encoded = encoded.drop(columns=["src_ip", "dst_ip"], errors="ignore")

    return encoded


def flow_summary(df: pd.DataFrame) -> dict:
    """Produce a small human-readable summary of a flow DataFrame."""
    return {
        "flows": int(len(df)),
        "columns": list(df.columns),
        "protocol_counts": (
            df["protocol"].value_counts().to_dict()
            if "protocol" in df.columns
            else {}
        ),
        "total_packets": int(df["packets"].sum()) if "packets" in df.columns else 0,
        "total_bytes": int(df["total_bytes"].sum()) if "total_bytes" in df.columns else 0,
    }
