"""pyntrace alert manager — webhook and threshold-based alerting."""
from __future__ import annotations

import json
import re
import time
import urllib.request
from dataclasses import dataclass, field
from typing import Any


@dataclass
class AlertRule:
    """A threshold-based alert rule."""

    metric: str          # "vulnerability_rate" | "cost_usd" | "scan_failed"
    operator: str        # ">" | ">=" | "<" | "<=" | "=="
    threshold: float
    severity: str = "medium"   # "low" | "medium" | "high" | "critical"
    cooldown_s: int = 300      # minimum seconds between repeated alerts
    _last_fired: float = field(default=0.0, repr=False, compare=False)

    def matches(self, metric: str, value: float) -> bool:
        if self.metric != metric:
            return False
        ops = {">": lambda a, b: a > b, ">=": lambda a, b: a >= b,
               "<": lambda a, b: a < b, "<=": lambda a, b: a <= b,
               "==": lambda a, b: a == b}
        return ops.get(self.operator, lambda *_: False)(value, self.threshold)

    def is_cooled_down(self) -> bool:
        return (time.time() - self._last_fired) >= self.cooldown_s

    def mark_fired(self) -> None:
        self._last_fired = time.time()


_CONDITION_RE = re.compile(
    r"^([\w_]+)\s*(>=|<=|>|<|==)\s*([\d.]+)$"
)

_SEVERITY_COLORS = {
    "low": "#36a64f",
    "medium": "#ff9500",
    "high": "#e01e5a",
    "critical": "#8b0000",
}


class AlertManager:
    """
    Webhook-based alert manager for pyntrace scans.

    Usage::

        alerts = AlertManager(webhooks={"slack": "https://hooks.slack.com/..."})
        alerts.on("vulnerability_rate > 0.10", severity="high")
        alerts.on("cost_usd > 50.00", severity="medium")

        # Pass to red_team():
        report = red_team(chatbot, alert_manager=alerts)
    """

    def __init__(
        self,
        webhooks: dict[str, str] | None = None,
        timeout_s: int = 5,
    ) -> None:
        self._webhooks: dict[str, str] = webhooks or {}
        self._rules: list[AlertRule] = []
        self._timeout = timeout_s

    def add_rule(self, rule: AlertRule) -> "AlertManager":
        """Add an AlertRule. Returns self for fluent chaining."""
        self._rules.append(rule)
        return self

    def on(self, condition: str, severity: str = "medium", cooldown_s: int = 300) -> "AlertManager":
        """
        Add a rule from a DSL string like ``"vulnerability_rate > 0.10"``.
        Returns self for fluent chaining.
        """
        m = _CONDITION_RE.match(condition.strip())
        if not m:
            raise ValueError(
                f"Invalid condition {condition!r}. "
                "Expected format: 'metric_name operator threshold' "
                "(e.g. 'vulnerability_rate > 0.10')"
            )
        metric, op, threshold = m.group(1), m.group(2), float(m.group(3))
        return self.add_rule(AlertRule(
            metric=metric,
            operator=op,
            threshold=threshold,
            severity=severity,
            cooldown_s=cooldown_s,
        ))

    def check(self, metric: str, value: float, context: dict[str, Any] | None = None) -> list[AlertRule]:
        """
        Evaluate rules against a metric value. Fire webhooks for matching
        rules that have cooled down. Returns list of fired rules.
        """
        fired = []
        for rule in self._rules:
            if rule.matches(metric, value) and rule.is_cooled_down():
                rule.mark_fired()
                self.fire(
                    event=f"{metric}_{rule.operator.replace('>','gt').replace('<','lt')}_{rule.threshold}",
                    data={
                        "metric": metric,
                        "value": value,
                        "threshold": rule.threshold,
                        "operator": rule.operator,
                        "severity": rule.severity,
                        **(context or {}),
                    },
                    severity=rule.severity,
                )
                fired.append(rule)
        return fired

    def fire(self, event: str, data: dict[str, Any], severity: str = "medium") -> None:
        """Send an alert to all configured webhooks."""
        for name, url in self._webhooks.items():
            try:
                if "hooks.slack.com" in url or name == "slack":
                    payload = self._format_slack(event, data, severity)
                else:
                    payload = self._format_generic(event, data, severity)
                self._send(url, payload)
            except Exception:
                pass  # Never let alerting crash the scan

    def _format_slack(self, event: str, data: dict, severity: str) -> dict:
        color = _SEVERITY_COLORS.get(severity, "#888888")
        metric = data.get("metric", event)
        value = data.get("value", "")
        threshold = data.get("threshold", "")
        fn = data.get("fn_name", data.get("target_fn", ""))
        return {
            "attachments": [{
                "color": color,
                "title": f"[pyntrace] {severity.upper()} — {metric} alert",
                "text": (
                    f"*Metric:* `{metric}` = `{value}` "
                    f"(threshold: {data.get('operator', '>')} {threshold})\n"
                    + (f"*Function:* `{fn}`\n" if fn else "")
                    + f"*Severity:* {severity}"
                ),
                "footer": "pyntrace",
                "ts": int(time.time()),
            }]
        }

    def _format_generic(self, event: str, data: dict, severity: str) -> dict:
        return {
            "source": "pyntrace",
            "event": event,
            "severity": severity,
            "timestamp": time.time(),
            "data": data,
        }

    def _send(self, url: str, payload: dict) -> None:
        body = json.dumps(payload).encode()
        req = urllib.request.Request(
            url,
            data=body,
            headers={"Content-Type": "application/json", "User-Agent": "pyntrace/0.4.0"},
            method="POST",
        )
        with urllib.request.urlopen(req, timeout=self._timeout):
            pass
