"""Built-in detection rules for network threat identification.

Each rule operates on a flow-level DataFrame (output of
``src.features.flows_to_dataframe``) and produces ``ThreatAlert`` objects
for suspicious patterns. Rules are re-evaluated independently, so the
``RuleEngine`` can run them in any order and merge the results.

Current catalog:
    - Port Scan      (T1046)  - many destination ports probed on a host
    - SYN Flood      (T1498)  - high-volume incomplete handshakes
    - Ping Sweep     (T1018)  - ICMP reachability sweep across hosts
    - ARP Spoofing   (T1557)  - conflicting MAC claims for the same IP
"""

import logging
from abc import ABC, abstractmethod

import pandas as pd

from .alerts import ThreatAlert

logger = logging.getLogger(__name__)


class BaseRule(ABC):
    name: str = "BaseRule"
    severity: str = "medium"

    @abstractmethod
    def evaluate(self, df: pd.DataFrame) -> list[ThreatAlert]: ...


class PortScanRule(BaseRule):
    """Detect hosts that probe many distinct destination ports on a target."""

    name = "Port Scan"
    severity = "high"

    def __init__(self, min_unique_ports: int = 15, max_pkts_per_flow: int = 3):
        self.min_unique_ports = min_unique_ports
        self.max_pkts_per_flow = max_pkts_per_flow

    def evaluate(self, df: pd.DataFrame) -> list[ThreatAlert]:
        alerts = []
        tcp_udp = df[df["protocol"].isin(["TCP", "UDP"])].copy()
        if tcp_udp.empty:
            return alerts

        rows = (
            tcp_udp.groupby(["src_ip", "dst_ip"])
            .agg(
                unique_ports=("dst_port", "nunique"),
                total_pkts=("packets", "sum"),
            )
            .reset_index()
            .to_dict("records")
        )

        for rec in rows:
            src_ip = str(rec["src_ip"])
            dst_ip = str(rec["dst_ip"])
            unique_ports = int(rec["unique_ports"])
            if unique_ports < self.min_unique_ports:
                continue
            confidence = min(unique_ports / (self.min_unique_ports * 3), 1.0)
            total_pkts = int(rec["total_pkts"])
            alerts.append(
                ThreatAlert(
                    rule_name=self.name,
                    severity=self.severity,
                    confidence=round(confidence, 2),
                    src_ip=str(src_ip),
                    dst_ip=str(dst_ip),
                    description=(
                        f"{unique_ports} unique ports probed on {dst_ip} "
                        f"with {total_pkts} total packets"
                    ),
                    evidence={
                        "unique_ports": unique_ports,
                        "total_pkts": total_pkts,
                    },
                )
            )
        return alerts


class SynFloodRule(BaseRule):
    """Detect hosts flooding a target with SYN-only handshakes."""

    name = "SYN Flood"
    severity = "critical"

    def __init__(self, min_syn_count: int = 20, min_syn_ratio: float = 0.7):
        self.min_syn_count = min_syn_count
        self.min_syn_ratio = min_syn_ratio

    def evaluate(self, df: pd.DataFrame) -> list[ThreatAlert]:
        alerts = []
        tcp = df[df["protocol"] == "TCP"]
        if tcp.empty:
            return alerts

        rows = (
            tcp.groupby("src_ip")
            .agg(total_syn=("syn_packets", "sum"), total_pkts=("packets", "sum"))
            .reset_index()
            .to_dict("records")
        )

        for rec in rows:
            src_ip = str(rec["src_ip"])
            total_syn = int(rec["total_syn"])
            total_pkts = int(rec["total_pkts"])
            if total_syn < self.min_syn_count:
                continue
            ratio = total_syn / total_pkts if total_pkts > 0 else 0.0
            if ratio < self.min_syn_ratio:
                continue
            confidence = min(ratio * (total_syn / (self.min_syn_count * 2)), 1.0)
            alerts.append(
                ThreatAlert(
                    rule_name=self.name,
                    severity=self.severity,
                    confidence=round(confidence, 2),
                    src_ip=str(src_ip),
                    dst_ip=None,
                    description=(
                        f"{total_syn} SYN packets ({ratio:.0%} of total) "
                        f"from {src_ip}"
                    ),
                    evidence={
                        "total_syn": total_syn,
                        "total_pkts": total_pkts,
                        "syn_ratio": round(ratio, 3),
                    },
                )
            )
        return alerts


class PingSweepRule(BaseRule):
    """Detect ICMP reachability sweeps across many unique hosts."""

    name = "Ping Sweep"
    severity = "medium"

    def __init__(self, min_unique_hosts: int = 5):
        self.min_unique_hosts = min_unique_hosts

    def evaluate(self, df: pd.DataFrame) -> list[ThreatAlert]:
        alerts = []
        icmp = df[df["protocol"] == "ICMP"]
        if icmp.empty:
            return alerts

        rows = (
            icmp.groupby("src_ip")
            .agg(unique_hosts=("dst_ip", "nunique"))
            .reset_index()
            .to_dict("records")
        )

        for rec in rows:
            src_ip = str(rec["src_ip"])
            unique_hosts = int(rec["unique_hosts"])
            if unique_hosts < self.min_unique_hosts:
                continue
            confidence = min(unique_hosts / (self.min_unique_hosts * 3), 1.0)
            alerts.append(
                ThreatAlert(
                    rule_name=self.name,
                    severity=self.severity,
                    confidence=round(confidence, 2),
                    src_ip=str(src_ip),
                    dst_ip=None,
                    description=(
                        f"ICMP echo requests to {unique_hosts} "
                        f"unique hosts from {src_ip}"
                    ),
                    evidence={"unique_hosts": unique_hosts},
                )
            )
        return alerts


class ArpSpoofRule(BaseRule):
    """Detect ARP cache-poisoning / spoofing patterns.

    Flags a claimed IP when it is advertised from multiple distinct MAC
    addresses (a classic cache-poisoning signature) or when a single host
    emits a high volume of unsolicited ARP replies toward many targets.
    """

    name = "ARP Spoofing"
    severity = "high"

    def __init__(self, min_replies: int = 5, min_macs: int = 2, min_targets: int = 1):
        self.min_replies = min_replies
        self.min_macs = min_macs
        self.min_targets = min_targets

    def evaluate(self, df: pd.DataFrame) -> list[ThreatAlert]:
        alerts = []
        if "protocol" not in df.columns:
            return alerts
        arp = df[df["protocol"] == "ARP"]
        if arp.empty:
            return alerts

        macs_by_src: dict[str, set] = {}
        replies_by_src: dict[str, int] = {}
        targets_by_src: dict[str, set] = {}

        for row in arp.itertuples(name="ArpRow"):
            src = str(getattr(row, "src_ip", "") or "")
            if not src:
                continue
            mac_field = str(getattr(row, "arp_hwsrc", "") or "")
            for mac in mac_field.split("|"):
                if mac:
                    macs_by_src.setdefault(src, set()).add(mac)
            replies_by_src[src] = replies_by_src.get(src, 0) + int(
                getattr(row, "arp_replies", 0) or 0
            )
            targets_by_src.setdefault(src, set()).add(
                str(getattr(row, "dst_ip", "") or "")
            )

        for src, macs in macs_by_src.items():
            replies = replies_by_src.get(src, 0)
            targets = len(targets_by_src.get(src, set()))

            if len(macs) >= self.min_macs:
                evidence = {
                    "conflicting_macs": sorted(macs),
                    "total_replies": replies,
                    "num_targets": targets,
                }
                confidence = min(len(macs) / (self.min_macs * 2), 1.0)
                alerts.append(
                    ThreatAlert(
                        rule_name=self.name,
                        severity="high",
                        confidence=round(confidence, 2),
                        src_ip=src,
                        dst_ip=None,
                        description=(
                            f"IP {src} advertised from {len(macs)} distinct MAC "
                            f"addresses ({evidence['conflicting_macs']}) — "
                            f"possible ARP cache poisoning"
                        ),
                        evidence=evidence,
                    )
                )
            elif replies >= self.min_replies and targets >= self.min_targets:
                alerts.append(
                    ThreatAlert(
                        rule_name=self.name,
                        severity="medium",
                        confidence=0.5,
                        src_ip=src,
                        dst_ip=None,
                        description=(
                            f"High volume of ARP replies ({replies}) from {src} "
                            f"toward {targets} target(s) — possible spoofing"
                        ),
                        evidence={
                            "total_replies": replies,
                            "num_targets": targets,
                            "confirmed_conflict": False,
                        },
                    )
                )
        return alerts