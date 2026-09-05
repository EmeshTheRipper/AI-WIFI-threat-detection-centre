"""Pipeline consistency: live-parsed packets and PCAP replay must converge.

The same flow-level features must be produced whether packets arrive from a
live sniffer (in-memory scapy objects) or are replayed from a PCAP file.
This guarantees the hybrid engine's downstream analysis is ingestion-agnostic.
"""

import pandas as pd
from scapy.layers.inet import ICMP, IP, TCP, UDP
from scapy.layers.l2 import ARP, Ether
from scapy.utils import wrpcap

from src.capture import PcapReader, parse_packets
from src.features import extract_flows, flows_to_dataframe


def _synthetic_packets():
    eth = lambda mac="00:11:22:33:44:55": Ether(src=mac, dst="ff:ff:ff:ff:ff:ff")
    return [
        eth() / IP(src="192.168.1.10", dst="10.0.0.1") / TCP(sport=1000, dport=443, flags="S"),
        eth() / IP(src="192.168.1.10", dst="10.0.0.1") / TCP(sport=1000, dport=443, flags="A"),
        eth() / IP(src="192.168.1.11", dst="8.8.8.8") / UDP(sport=5353, dport=53),
        eth() / IP(src="10.0.0.2", dst="10.0.0.3") / ICMP(type=8, code=0),
        eth() / ARP(op=2, psrc="10.0.0.1", pdst="10.0.0.5", hwsrc="00:11:22:33:44:55"),
    ]


def _flows_df(records):
    return flows_to_dataframe(extract_flows(records))


def _sorted(df):
    keys = [c for c in ["src_ip", "dst_ip", "protocol", "src_port", "dst_port"]
            if c in df.columns]
    return df.sort_values(keys).reset_index(drop=True)


def test_parse_and_write_cheap(tmp_path):
    packets = _synthetic_packets()
    pcap = tmp_path / "mixed.pcap"
    wrpcap(str(pcap), packets)
    replayed = list(PcapReader(str(pcap)).read_all())
    assert len(replayed) == len(packets)


def test_live_and_pcap_paths_identical(tmp_path):
    packets = _synthetic_packets()

    # Live path: packet objects parsed in-memory (sniffer callback path).
    live_df = _flows_df(parse_packets(packets))

    # PCAP path: packets serialized, re-read, then parsed.
    pcap = tmp_path / "mixed.pcap"
    wrpcap(str(pcap), packets)
    pcap_df = _flows_df(parse_packets(PcapReader(str(pcap)).read_all()))

    assert set(live_df["protocol"]) == set(pcap_df["protocol"])
    assert set(live_df["protocol"]) == {"TCP", "UDP", "ICMP", "ARP"}
    pd.testing.assert_frame_equal(_sorted(live_df), _sorted(pcap_df))


def test_live_path_includes_arp_flow_features():
    live_df = _flows_df(parse_packets(_synthetic_packets()))
    arp = live_df[live_df["protocol"] == "ARP"]
    assert len(arp) == 1
    row = arp.iloc[0]
    assert row["arp_replies"] == 1
    assert row["arp_unique_hwsrc"] == 1
    assert row["arp_hwsrc"] == "00:11:22:33:44:55"