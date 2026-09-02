"""End-to-end pipeline: PCAP -> parsed records -> flows -> DataFrame."""

import logging

from src.capture import PcapReader, parse_packets
from src.features.builder import encode_features, flows_to_dataframe
from src.features.extractor import extract_flows

logger = logging.getLogger(__name__)


def build_features_from_pcap(
    filepath: str,
    encode: bool = True,
    drop_ips: bool = True,
):
    """Load a PCAP file and compute a feature DataFrame from its traffic.

    Returns:
        (dataframe, summary) where summary is a dict of diagnostics.
    """
    reader = PcapReader(filepath)
    records = parse_packets(reader.read_all())
    flows = extract_flows(records)
    df = flows_to_dataframe(flows)
    if encode:
        df = encode_features(df, drop_ips=drop_ips)
    logger.info("Feature pipeline complete: %d flows", len(df))
    return df, {"raw_records": len(records), "flows": len(flows), "shape": df.shape}
