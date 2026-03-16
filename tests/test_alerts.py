"""Tests for AlertManager and AlertRule."""
import json
import pytest
from unittest.mock import patch, MagicMock
from pyntrace.monitor.alerts import AlertManager, AlertRule


class TestAlertRule:
    def test_matches_gt(self):
        rule = AlertRule(metric="vulnerability_rate", operator=">", threshold=0.1)
        assert rule.matches("vulnerability_rate", 0.2) is True
        assert rule.matches("vulnerability_rate", 0.05) is False
        assert rule.matches("vulnerability_rate", 0.1) is False

    def test_matches_gte(self):
        rule = AlertRule(metric="cost_usd", operator=">=", threshold=5.0)
        assert rule.matches("cost_usd", 5.0) is True
        assert rule.matches("cost_usd", 6.0) is True
        assert rule.matches("cost_usd", 4.9) is False

    def test_matches_lt(self):
        rule = AlertRule(metric="score", operator="<", threshold=0.5)
        assert rule.matches("score", 0.3) is True
        assert rule.matches("score", 0.5) is False

    def test_matches_lte(self):
        rule = AlertRule(metric="score", operator="<=", threshold=0.5)
        assert rule.matches("score", 0.5) is True
        assert rule.matches("score", 0.6) is False

    def test_matches_eq(self):
        rule = AlertRule(metric="flag", operator="==", threshold=1.0)
        assert rule.matches("flag", 1.0) is True
        assert rule.matches("flag", 2.0) is False

    def test_wrong_metric(self):
        rule = AlertRule(metric="vulnerability_rate", operator=">", threshold=0.1)
        assert rule.matches("cost_usd", 100.0) is False

    def test_cooldown(self):
        rule = AlertRule(metric="x", operator=">", threshold=0, cooldown_s=300)
        assert rule.is_cooled_down() is True
        rule.mark_fired()
        assert rule.is_cooled_down() is False

    def test_zero_cooldown(self):
        rule = AlertRule(metric="x", operator=">", threshold=0, cooldown_s=0)
        rule.mark_fired()
        assert rule.is_cooled_down() is True


class TestAlertManager:
    def test_on_parses_gt(self):
        am = AlertManager()
        am.on("vulnerability_rate > 0.10", severity="high")
        assert len(am._rules) == 1
        r = am._rules[0]
        assert r.metric == "vulnerability_rate"
        assert r.operator == ">"
        assert r.threshold == 0.10
        assert r.severity == "high"

    def test_on_parses_gte(self):
        am = AlertManager()
        am.on("cost_usd >= 50.00")
        r = am._rules[0]
        assert r.operator == ">="
        assert r.threshold == 50.0

    def test_on_invalid_condition(self):
        am = AlertManager()
        with pytest.raises(ValueError, match="Invalid condition"):
            am.on("not a valid condition")

    def test_fluent_chaining(self):
        am = AlertManager()
        result = am.on("vulnerability_rate > 0.1").on("cost_usd > 10")
        assert result is am
        assert len(am._rules) == 2

    def test_add_rule(self):
        am = AlertManager()
        rule = AlertRule(metric="x", operator=">", threshold=1.0)
        am.add_rule(rule)
        assert len(am._rules) == 1

    def test_check_fires_matching_rule(self):
        fired_events = []

        am = AlertManager()
        am.on("vulnerability_rate > 0.10", severity="high")

        with patch.object(am, "fire") as mock_fire:
            result = am.check("vulnerability_rate", 0.50)
            assert len(result) == 1
            mock_fire.assert_called_once()

    def test_check_no_fire_below_threshold(self):
        am = AlertManager()
        am.on("vulnerability_rate > 0.10")
        with patch.object(am, "fire") as mock_fire:
            result = am.check("vulnerability_rate", 0.05)
            assert result == []
            mock_fire.assert_not_called()

    def test_check_respects_cooldown(self):
        am = AlertManager()
        am.on("vulnerability_rate > 0.10", cooldown_s=300)
        with patch.object(am, "fire") as mock_fire:
            am.check("vulnerability_rate", 0.50)
            am.check("vulnerability_rate", 0.50)
            assert mock_fire.call_count == 1  # second call blocked by cooldown

    def test_send_called_on_fire(self):
        am = AlertManager(webhooks={"slack": "https://hooks.slack.com/test"})
        with patch.object(am, "_send") as mock_send:
            am.fire("test_event", {"metric": "vulnerability_rate", "value": 0.5}, severity="high")
            mock_send.assert_called_once()

    def test_format_slack(self):
        am = AlertManager()
        payload = am._format_slack("vuln_gt_0.1", {"metric": "vulnerability_rate", "value": 0.5, "threshold": 0.1, "operator": ">"}, "high")
        assert "attachments" in payload
        assert payload["attachments"][0]["title"]
        assert "HIGH" in payload["attachments"][0]["title"]

    def test_format_generic(self):
        am = AlertManager()
        payload = am._format_generic("test_event", {"metric": "cost_usd", "value": 100}, "medium")
        assert payload["source"] == "pyntrace"
        assert payload["event"] == "test_event"
        assert payload["severity"] == "medium"

    def test_send_uses_urllib(self):
        am = AlertManager()
        with patch("urllib.request.urlopen") as mock_urlopen:
            ctx = MagicMock()
            ctx.__enter__ = MagicMock(return_value=ctx)
            ctx.__exit__ = MagicMock(return_value=False)
            mock_urlopen.return_value = ctx
            am._send("https://example.com/webhook", {"test": True})
            mock_urlopen.assert_called_once()

    def test_fire_does_not_raise_on_error(self):
        am = AlertManager(webhooks={"slack": "https://example.com"})
        with patch.object(am, "_send", side_effect=Exception("network error")):
            am.fire("test", {})  # must not raise

    def test_no_webhooks_no_send(self):
        am = AlertManager()
        with patch.object(am, "_send") as mock_send:
            am.fire("test", {})
            mock_send.assert_not_called()
