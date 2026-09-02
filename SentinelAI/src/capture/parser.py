import logging
from datetime import datetime, timezone

from scapy.all import DNS, ICMP, IP, TCP, UDP, Raw

logger = logging.getLogger(__name__)


def parse_packet(packet) -> dict | None:
    """Extract structured data from a scapy packet.

    Returns a dict with normalized fields for downstream processing,
    or None if the packet lacks usable network-layer info.
    """
    record = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "protocol": None,
        "src_ip": None,
        "dst_ip": None,
        "src_port": None,
        "dst_port": None,
        "length": len(packet),
        "flags": None,
        "payload_size": 0,
        "payload_sample": None,
    }

    if IP in packet:
        record["src_ip"] = packet[IP].src
        record["dst_ip"] = packet[IP].dst
        record["protocol"] = packet[IP].proto
    else:
        return None

    if TCP in packet:
        record["protocol"] = "TCP"
        record["src_port"] = packet[TCP].sport
        record["dst_port"] = packet[TCP].dport
        record["flags"] = str(packet[TCP].flags)
    elif UDP in packet:
        record["protocol"] = "UDP"
        record["src_port"] = packet[UDP].sport
        record["dst_port"] = packet[UDP].dport
    elif ICMP in packet:
        record["protocol"] = "ICMP"
        record["flags"] = f"type={packet[ICMP].type} code={packet[ICMP].code}"

    if Raw in packet:
        raw = bytes(packet[Raw].load)
        record["payload_size"] = len(raw)
        record["payload_sample"] = raw[:64].hex()

    if DNS in packet:
        record["dns_query"] = packet[DNS].qd.qname.decode() if packet[DNS].qd else None

    return record


def parse_packets(packets) -> list[dict]:
    """Parse a list/iterator of packets into structured records."""
    records = []
    total = 0
    for pkt in packets:
        total += 1
        record = parse_packet(pkt)
        if record:
            records.append(record)
    logger.info("Parsed %d packets into %d records", total, len(records))
    return records
