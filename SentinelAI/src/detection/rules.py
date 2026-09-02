"""Built-in detection rules for network threat identification.

Each rule operates on a flow-level DataFrame and produces ThreatAlert
objects for suspicious patterns.
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

        grouped = tcp_udp.groupby("src_ip").apply(
            lambda g: pd.DataFrame(
                {
                    "dst_ip": g["dst_ip"],
                    "unique_ports": g.groupby("dst_ip")["dst_port"].transform("nunique"),
                    "pkts": g["packets"],
                }
            ),
            include_groups=False,
        ).reset_index(level=0).rename(columns={"level_0": "src_ip"})

        for src_ip, group in grouped.groupby("src_ip"):
            ports_per_host = group.groupby("dst_ip").agg(
                unique_ports=("unique_ports", "first"),
                total_pkts=("pkts", "sum"),
            )
            for dst_ip, row in ports_per_host.iterrows():
                if row["unique_ports"] >= self.min_unique_ports:
                    confidence = min(row["unique_ports"] / (self.min_unique_ports * 3), 1.0)
                    alerts.append(
                        ThreatAlert(
                            rule_name=self.name,
                            severity=self.severity,
                            confidence=round(confidence, 2),
                            src_ip=src_ip,
                            dst_ip=dst_ip,
                            description=(
                                f"{int(row['unique_ports'])} unique ports probed on {dst_ip} "
                                f"with {int(row['total_pkts'])} total packets"
                            ),
                            evidence={
                                "unique_ports": int(row["unique_ports"]),
                                "total_pkts": int(row["total_pkts"]),
                            },
                        )
                    )
        return alerts


class SynFloodRule(BaseRule):
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

        agg = tcp.groupby("src_ip").agg(
            total_syn=("syn_packets", "sum"),
            total_pkts=("packets", "sum"),
        )

        for src_ip, row in agg.iterrows():
            if row["total_syn"] >= self.min_syn_count:
                ratio = row["total_syn"] / row["total_pkts"] if row["total_pkts"] > 0 else 0
                if ratio >= self.min_syn_ratio:
                    confidence = min(ratio * (row["total_syn"] / (self.min_syn_count * 2)), 1.0)
                    alerts.append(
                        ThreatAlert(
                            rule_name=self.name,
                            severity=self.severity,
                            confidence=round(confidence, 2),
                            src_ip=src_ip,
                            dst_ip=None,
                            description=(
                                f"{int(row['total_syn'])} SYN packets ({ratio:.0%} of total) "
                                f"from {src_ip}"
                            ),
                            evidence={
                                "total_syn": int(row["total_syn"]),
                                "total_pkts": int(row["total_pkts"]),
                                "syn_ratio": round(ratio, 3),
                            },
                        )
                    )
        return alerts


class PingSweepRule(BaseRule):
    name = "Ping Sweep"
    severity = "medium"

    def __init__(self, min_unique_hosts: int = 5):
        self.min_unique_hosts = min_unique_hosts

    def evaluate(self, df: pd.DataFrame) -> list[ThreatAlert]:
        alerts = []
        icmp = df[df["protocol"] == "ICMP"]
        if icmp.empty:
            return alerts

        agg = icmp.groupby("src_ip")["dst_ip"].nunique().reset_index()
        agg.columns = ["src_ip", "unique_hosts"]

        for _, row in agg.iterrows():
            if row["unique_hosts"] >= self.min_unique_hosts:
                confidence = min(row["unique_hosts"] / (self.min_unique_hosts * 3), 1.0)
                alerts.append(
                    ThreatAlert(
                        rule_name=self.name,
                        severity=self.severity,
                        confidence=round(confidence, 2),
                        src_ip=row["src_ip"],
                        dst_ip=None,
                        description=(
                            f"ICMP echo requests to {int(row['unique_hosts'])} "
                            f"unique hosts from {row['src_ip']}"
                        ),
                        evidence={"unique_hosts": int(row["unique_hosts"])},
                    )
                )
        return alerts
