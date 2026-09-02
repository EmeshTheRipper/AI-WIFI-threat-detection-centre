"""Tests for the feature engineering module."""

import pandas as pd

from src.features import (
    build_features_from_pcap,
    encode_features,
    extract_flows,
    flow_key,
    flows_to_dataframe,
)
from src.features.builder import flow_summary
from tests.fixtures import make_flow_records


def test_flow_key_groups_by_5_tuple():
    record = make_flow_records()[0]
    assert flow_key(record) == ("192.168.1.10", 1000, "10.0.0.1", 443, "TCP")


def test_extract_flows_aggregates_packets():
    flows = extract_flows(make_flow_records())
    assert len(flows) == 3  # 2x TCP + 1x ICMP
    tcp_flow = next(f for f in flows if f["src_port"] == 1000)
    assert tcp_flow["packets"] == 2
    assert tcp_flow["syn_packets"] == 2
    assert tcp_flow["total_bytes"] == 120  # 50 + 70
    assert tcp_flow["mean_size"] == 60.0


def test_flows_to_dataframe_numeric_types():
    df = flows_to_dataframe(extract_flows(make_flow_records()))
    assert isinstance(df, pd.DataFrame)
    assert "packets" in df.columns
    assert pd.api.types.is_numeric_dtype(df["packets"])
    assert df["mean_size"].dtype == float


def test_encode_features_adds_protocol_dummies():
    df = flows_to_dataframe(extract_flows(make_flow_records()))
    encoded = encode_features(df, drop_ips=True)
    assert "src_ip" not in encoded.columns
    assert "proto_TCP" in encoded.columns
    assert "proto_ICMP" in encoded.columns
    tcp_row = encoded[encoded["proto_TCP"] == 1].iloc[0]
    assert tcp_row["proto_ICMP"] == 0


def test_flow_summary_counts():
    df = flows_to_dataframe(extract_flows(make_flow_records()))
    summary = flow_summary(df)
    assert summary["flows"] == 3


def test_build_features_from_pcap(tmp_path):
    from scapy.all import IP, TCP, wrpcap

    pcap = tmp_path / "sample.pcap"
    packets = [
        IP(src="192.168.1.10", dst="10.0.0.1") / TCP(sport=1000, dport=443, flags="S")
        for _ in range(5)
    ]
    wrpcap(str(pcap), packets)

    df, summary = build_features_from_pcap(str(pcap))
    assert summary["raw_records"] == 5
    assert summary["flows"] == 1
    assert df["proto_TCP"].iloc[0] == 1
