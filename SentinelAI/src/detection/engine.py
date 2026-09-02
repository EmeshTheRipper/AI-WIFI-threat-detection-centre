"""Detection engine that orchestrates rule evaluation."""

import logging

import pandas as pd

from .alerts import SEVERITY_ORDER, ThreatAlert
from .rules import BaseRule, PingSweepRule, PortScanRule, SynFloodRule

logger = logging.getLogger(__name__)

DEFAULT_RULES = [PortScanRule(), SynFloodRule(), PingSweepRule()]


class RuleEngine:
    def __init__(self, rules: list[BaseRule] | None = None):
        self.rules = rules if rules is not None else list(DEFAULT_RULES)
        logger.info("RuleEngine initialized with %d rules", len(self.rules))

    def analyze(self, df: pd.DataFrame) -> list[ThreatAlert]:
        alerts: list[ThreatAlert] = []
        for rule in self.rules:
            rule_alerts = rule.evaluate(df)
            if rule_alerts:
                logger.info("%s triggered %d alert(s)", rule.name, len(rule_alerts))
            alerts.extend(rule_alerts)

        alerts.sort(key=lambda a: SEVERITY_ORDER.get(a.severity, 0), reverse=True)
        logger.info("Total alerts: %d", len(alerts))
        return alerts

    def summary(self, alerts: list[ThreatAlert]) -> dict:
        by_severity = {}
        for a in alerts:
            by_severity[a.severity] = by_severity.get(a.severity, 0) + 1
        by_rule = {}
        for a in alerts:
            by_rule[a.rule_name] = by_rule.get(a.rule_name, 0) + 1
        return {
            "total": len(alerts),
            "by_severity": by_severity,
            "by_rule": by_rule,
        }
