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
    "arp_requests",
    "arp_replies",
    "arp_unique_hwsrc",
]

CATEGORICAL_FLOW_FIELDS = [
    "protocol",
]


def flows_to_dataframe(flows: list[dict]) -> pd.DataFrame:
    """Convert a list of flow dicts into a numeric-feature DataFrame.

    Args:
        flows: Flow feature dicts from ``extract_flows``.

    Returns:
        A DataFrame with numeric flow features coerced and ``protocol``
        stored as a categorical column.
    """
    df = pd.DataFrame(flows)

    for field in NUMERIC_FLOW_FIELDS:
        if field in df.columns:
            numeric = pd.to_numeric(df[field], errors="coerce")
            if isinstance(numeric, pd.Series):
                numeric = numeric.fillna(0)
            df[field] = numeric

    if "protocol" in df.columns:
        df["protocol"] = df["protocol"].astype("category")

    logger.info("Built DataFrame with %d rows x %d cols", *df.shape)
    return df


def encode_features(df: pd.DataFrame, drop_ips: bool = True) -> pd.DataFrame:
    """Encode categorical features for ML.

    Args:
        df: DataFrame from ``flows_to_dataframe``.
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


def _sum_column(df: pd.DataFrame, column: str) -> int:
    """Return the scalar sum of a column, defaulting to 0 when absent."""
    if column not in df.columns:
        return 0
    values = df[column]
    if isinstance(values, pd.Series):
        return int(values.sum())
    return 0


def flow_summary(df: pd.DataFrame) -> dict:
    """Produce a small human-readable summary of a flow DataFrame.

    Returns:
        dict with flow count, column list, protocol distribution, and
        aggregated packet/byte totals.
    """
    protocol_counts: dict = {}
    if "protocol" in df.columns:
        proto = df["protocol"]
        if isinstance(proto, pd.Series):
            protocol_counts = proto.value_counts().to_dict()

    return {
        "flows": int(len(df)),
        "columns": list(df.columns),
        "protocol_counts": protocol_counts,
        "total_packets": _sum_column(df, "packets"),
        "total_bytes": _sum_column(df, "total_bytes"),
    }