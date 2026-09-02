"""Flow-level feature extraction from parsed packet records.

A network *flow* is a unidirectional stream of packets sharing the same
5-tuple: src_ip, src_port, dst_ip, dst_port, protocol. Attack signatures
often manifest as statistical differences in these aggregated flows.
"""

import logging
from collections import defaultdict

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
        # ICMP flows carry no ports; require only IPs and protocol
        if not key or None in (key[0], key[2], key[4]):
            continue
        grouped[key].append(record)

    flows = [_aggregate_flow(key, packets) for key, packets in grouped.items()]
    logger.info("Built %d flows from %d packets", len(flows), len(records))
    return flows


def _aggregate_flow(key: tuple, packets: list[dict]) -> dict:
    src_ip, src_port, dst_ip, dst_port, protocol = key
    sizes = [p["length"] for p in packets]
    payloads = [p["payload_size"] for p in packets]

    syn_count = sum(
        1
        for p in packets
        if p.get("flags") and "S" in str(p["flags"]) and "A" not in str(p["flags"])
    )
    rst_count = sum(1 for p in packets if p.get("flags") and "R" in str(p["flags"]))

    return {
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
        "std_size": round(_std(sizes), 2),
        "total_payload": sum(payloads),
        "mean_payload": round(sum(payloads) / len(payloads), 2),
        "syn_packets": syn_count,
        "rst_packets": rst_count,
    }


def _std(values: list) -> float:
    if len(values) < 2:
        return 0.0
    mean = sum(values) / len(values)
    variance = sum((v - mean) ** 2 for v in values) / (len(values) - 1)
    return variance**0.5
