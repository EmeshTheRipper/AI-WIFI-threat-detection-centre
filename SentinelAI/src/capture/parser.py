"""Scapy packet -> structured record parser.

Normalizes raw scapy packets (from live capture or PCAP reads) into a
consistent ``dict`` schema so both ingestion paths (live sniffing and file
replay) feed the identical feature-engineering pipeline.

Supported protocols: IP/TCP, IP/UDP, IP/ICMP, DNS queries (payload-level
annotation) and ARP. Non-IP packets (e.g. bare Ethernet frames without a
network layer) are skipped and yield ``None``.
"""

import logging
from datetime import datetime, timezone
from typing import Any

from scapy.layers.dns import DNS
from scapy.layers.inet import ICMP, IP, TCP, UDP
from scapy.layers.l2 import ARP
from scapy.packet import Packet, Raw

logger = logging.getLogger(__name__)


def _new_record(length: int) -> dict:
    """Initialize a record with the uniform packet schema."""
    return {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "protocol": None,
        "src_ip": None,
        "dst_ip": None,
        "src_port": None,
        "dst_port": None,
        "length": length,
        "flags": None,
        "payload_size": 0,
        "payload_sample": None,
        "dns_query": None,
        "arp_op": None,
        "arp_psrc": None,
        "arp_pdst": None,
        "arp_hwsrc": None,
        "arp_hwdst": None,
    }


def parse_packet(packet: Packet) -> dict[str, Any] | None:
    """Extract structured data from a scapy packet.

    Args:
        packet: A scapy ``Packet`` (any layer stack).

    Returns:
        A dict with normalized fields for downstream processing, or ``None``
        if the packet lacks usable network/link-layer info.
    """
    record = _new_record(len(packet))

    if ARP in packet:
        arp = packet[ARP]
        record["protocol"] = "ARP"
        record["src_ip"] = str(arp.psrc)
        record["dst_ip"] = str(arp.pdst)
        record["arp_op"] = int(arp.op)
        record["arp_psrc"] = str(arp.psrc)
        record["arp_pdst"] = str(arp.pdst)
        record["arp_hwsrc"] = str(arp.hwsrc)
        record["arp_hwdst"] = str(arp.hwdst)
        return record

    if IP not in packet:
        return None

    ip = packet[IP]
    record["src_ip"] = str(ip.src)
    record["dst_ip"] = str(ip.dst)
    record["protocol"] = ip.proto

    if TCP in packet:
        tcp = packet[TCP]
        record["protocol"] = "TCP"
        record["src_port"] = int(tcp.sport)
        record["dst_port"] = int(tcp.dport)
        record["flags"] = str(tcp.flags)
    elif UDP in packet:
        udp = packet[UDP]
        record["protocol"] = "UDP"
        record["src_port"] = int(udp.sport)
        record["dst_port"] = int(udp.dport)
    elif ICMP in packet:
        icmp = packet[ICMP]
        record["protocol"] = "ICMP"
        record["flags"] = f"type={icmp.type} code={icmp.code}"

    if Raw in packet:
        raw = bytes(packet[Raw].load)
        record["payload_size"] = len(raw)
        record["payload_sample"] = raw[:64].hex()

    if DNS in packet:
        dns_qd = packet[DNS].qd
        record["dns_query"] = dns_qd.qname.decode(errors="replace") if dns_qd else None

    return record


def parse_packets(packets) -> list[dict]:
    """Parse a list or iterator of scapy packets into structured records.

    Args:
        packets: Iterable of scapy packets.

    Returns:
        List of parsed record dicts (non-IP packets are skipped).
    """
    records = []
    total = 0
    for pkt in packets:
        total += 1
        record = parse_packet(pkt)
        if record:
            records.append(record)
    logger.info("Parsed %d packets into %d records", total, len(records))
    return records