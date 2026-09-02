"""Fixtures for feature-engineering tests.

Builds synthetic *parsed packet record* dicts (as produced by
src.capture.parser) rather than raw scapy packets, keeping feature tests
focused on flow aggregation logic.
"""


def make_record(
    src_ip="192.168.1.10",
    dst_ip="10.0.0.1",
    src_port=12345,
    dst_port=443,
    protocol="TCP",
    length=60,
    payload_size=10,
    flags="S",
):
    return {
        "timestamp": "2026-01-01T00:00:00+00:00",
        "protocol": protocol,
        "src_ip": src_ip,
        "dst_ip": dst_ip,
        "src_port": src_port,
        "dst_port": dst_port,
        "length": length,
        "flags": flags,
        "payload_size": payload_size,
        "payload_sample": "aa",
    }


def make_flow_records(filepath=None):
    return [
        # Two SYN packets to the same destination -> one flow, syn_packets=2
        make_record(src_port=1000, flags="S", length=50, payload_size=5),
        make_record(src_port=1000, flags="S", length=70, payload_size=15),
        # A different flow destination port
        make_record(src_port=2000, dst_port=8080, length=90),
        # An ICMP flow (no ports)
        make_record(protocol="ICMP", src_port=None, dst_port=None, flags="type=8 code=0"),
    ]
