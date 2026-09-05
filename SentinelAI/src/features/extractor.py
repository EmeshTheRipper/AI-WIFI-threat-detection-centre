"""Flow-level feature extraction from parsed packet records.

A network *flow* is a unidirectional stream of packets sharing the same
5-tuple: src_ip, src_port, dst_ip, dst_port, protocol. Attack signatures
often manifest as statistical differences in these aggregated flows.

ARP traffic has no ports, so its flows are keyed on
(src_ip, dst_ip, protocol) and additionally aggregate per-flow ARP metrics
(reply/request counts and distinct hardware addresses) to support
ARP-spoofing detection downstream.
"""

import logging
from collections import defaultdict
from statistics import pstdev
from typing import Any

logger = logging.getLogger(__name__)

AGGREGATED_FLOW_FIELDS = [
    "src_ip",
    "src_port",
    "dst_ip",
    "dst_port",
    "protocol",
]


def flow_key(record: dict) -> tuple:
    """Return the 5-tuple used to group packets into flows."""
    return tuple(record.get(f) for f in AGGREGATED_FLOW_FIELDS)


def extract_flows(records: list[dict]) -> list[dict]:
    """Group packet records into flows and compute statistical features.

    Args:
        records: Parsed packet records (list of dicts).

    Returns:
        A list of flow feature dicts, one per detected flow.
    """
    grouped: dict[tuple, list[dict]] = defaultdict(list)
    for record in records:
        key = flow_key(record)
        # IP/ARP flows need at least both addresses and a protocol.
        if not key or None in (key[0], key[2], key[4]):
            continue
        grouped[key].append(record)

    flows = [_aggregate_flow(key, packets) for key, packets in grouped.items()]
    logger.info("Built %d flows from %d packets", len(flows), len(records))
    return flows


def _aggregate_flow(key: tuple, packets: list[dict]) -> dict:
    src_ip, src_port, dst_ip, dst_port, protocol = key
    sizes = [int(p["length"]) for p in packets]
    payloads = [int(p["payload_size"]) for p in packets]

    syn_count = sum(
        1
        for p in packets
        if p.get("flags") and "S" in str(p["flags"]) and "A" not in str(p["flags"])
    )
    rst_count = sum(1 for p in packets if p.get("flags") and "R" in str(p["flags"]))

    flow: dict[str, Any] = {
        "src_ip": src_ip,
        "src_port": src_port,
        "dst_ip": dst_ip,
        "dst_port": dst_port,
        "protocol": protocol,
        "packets": len(packets),
        "total_bytes": sum(sizes),
        "min_size": min(sizes),
        "max_size": max(sizes),
        "mean_size": round(sum(sizes) / len(sizes), 2),
        "std_size": round(pstdev(sizes), 2),
        "total_payload": sum(payloads),
        "mean_payload": round(sum(payloads) / len(payloads), 2),
        "syn_packets": syn_count,
        "rst_packets": rst_count,
    }

    if protocol == "ARP":
        flow["arp_requests"] = sum(1 for p in packets if int(p.get("arp_op") or 0) == 1)
        flow["arp_replies"] = sum(1 for p in packets if int(p.get("arp_op") or 0) == 2)
        macs = {p.get("arp_hwsrc") for p in packets if p.get("arp_hwsrc")}
        flow["arp_unique_hwsrc"] = len(macs)
        flow["arp_hwsrc"] = "|".join(sorted(str(m) for m in macs))

    return flow