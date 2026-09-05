"""Tests for the capture module."""

from scapy.layers.inet import ICMP, IP, TCP, UDP
from scapy.layers.l2 import Ether
from scapy.packet import Raw

from src.capture import parse_packet


def make_tcp_packet():
    return (
        IP(src="192.168.1.10", dst="10.0.0.1")
        / TCP(sport=12345, dport=443, flags="S")
        / Raw(load=b"GET / HTTP/1.1")
    )


def test_parse_tcp_packet():
    record = parse_packet(make_tcp_packet())
    assert record is not None
    assert record["protocol"] == "TCP"
    assert record["src_ip"] == "192.168.1.10"
    assert record["dst_ip"] == "10.0.0.1"
    assert record["src_port"] == 12345
    assert record["dst_port"] == 443
    assert record["payload_size"] == 14


def test_parse_udp_packet():
    pkt = IP(src="192.168.1.11", dst="8.8.8.8") / UDP(sport=5353, dport=53)
    record = parse_packet(pkt)
    assert record is not None
    assert record["protocol"] == "UDP"
    assert record["dst_port"] == 53


def test_parse_icmp_packet():
    pkt = IP(src="10.0.0.2", dst="10.0.0.3") / ICMP(type=8, code=0)
    record = parse_packet(pkt)
    assert record is not None
    assert record["protocol"] == "ICMP"
    assert "type=8" in record["flags"]


def test_parse_arp_packet():
    from scapy.layers.l2 import ARP

    pkt = ARP(psrc="10.0.0.1", pdst="10.0.0.2", hwsrc="00:11:22:33:44:55", op=2)
    record = parse_packet(pkt)
    assert record is not None
    assert record["protocol"] == "ARP"
    assert record["src_ip"] == "10.0.0.1"
    assert record["arp_op"] == 2


def test_non_ip_packet_returns_none():
    pkt = Ether(dst="ff:ff:ff:ff:ff:ff")
    assert parse_packet(pkt) is None


def test_read_stream_yields_all_packets():
    from src.capture import PcapReader

    packets = list(PcapReader("data/samples/level2_sample.pcap").read_stream())
    assert len(packets) == 61