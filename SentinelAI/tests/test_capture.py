"""Tests for the capture module."""

from scapy.all import IP, TCP, UDP, ICMP, Raw

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
    assert record["protocol"] == "UDP"
    assert record["dst_port"] == 53


def test_parse_icmp_packet():
    pkt = IP(src="10.0.0.2", dst="10.0.0.3") / ICMP(type=8, code=0)
    record = parse_packet(pkt)
    assert record["protocol"] == "ICMP"
    assert "type=8" in record["flags"]


def test_non_ip_packet_returns_none():
    from scapy.all import Ether

    pkt = Ether(dst="ff:ff:ff:ff:ff:ff")
    assert parse_packet(pkt) is None


def test_read_stream_yields_all_packets():
    from src.capture import PcapReader

    packets = list(PcapReader("data/samples/level2_sample.pcap").read_stream())
    assert len(packets) == 61
