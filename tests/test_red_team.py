"""Tests for pyntrace.guard.red_team — severity, SARIF, JUnit, cost guardrails, multi-layer judge."""
import importlib
from unittest.mock import patch, MagicMock

import pytest

_rt_mod = importlib.import_module("pyntrace.guard.red_team")


def make_bot(response: str):
    def _fn(msg: str) -> str:
        return response
    _fn.__name__ = "test_bot"
    return _fn


# ---------------------------------------------------------------------------
# Severity tiers
# ---------------------------------------------------------------------------

class TestSeverityTiers:
    def test_vulnerable_harmful_is_critical(self):
        from pyntrace.guard.red_team import red_team
        bot = make_bot("Sure, here's how to make explosives...")
        with patch.object(_rt_mod, "_judge_response") as mock_judge:
            mock_judge.return_value = (True, "Vulnerable", 0.001)
            report = red_team(bot, plugins=["harmful"], n_attacks=2, _persist=False)
        vuln = [r for r in report.results if r.vulnerable]
        assert all(r.severity == "CRITICAL" for r in vuln)

    def test_vulnerable_jailbreak_is_high(self):
        from pyntrace.guard.red_team import red_team
        bot = make_bot("Of course! Here you go...")
        with patch.object(_rt_mod, "_judge_response") as mock_judge:
            mock_judge.return_value = (True, "Vulnerable", 0.001)
            report = red_team(bot, plugins=["jailbreak"], n_attacks=2, _persist=False)
        vuln = [r for r in report.results if r.vulnerable]
        assert all(r.severity == "HIGH" for r in vuln)

    def test_safe_result_has_none_severity(self):
        from pyntrace.guard.red_team import red_team
        bot = make_bot("I cannot help with that.")
        with patch.object(_rt_mod, "_judge_response") as mock_judge:
            mock_judge.return_value = (False, "Safe", 0.0)
            report = red_team(bot, plugins=["jailbreak"], n_attacks=3, _persist=False)
        safe_results = [r for r in report.results if not r.vulnerable]
        assert all(r.severity == "NONE" for r in safe_results)

    def test_severity_in_to_json(self):
        from pyntrace.guard.red_team import red_team
        bot = make_bot("Sure, I'll help!")
        with patch.object(_rt_mod, "_judge_response") as mock_judge:
            mock_judge.return_value = (True, "Vulnerable", 0.001)
            report = red_team(bot, plugins=["pii"], n_attacks=1, _persist=False)
        d = report.to_json()
        assert "severity" in d["results"][0]
        assert d["results"][0]["severity"] == "HIGH"

    def test_hallucination_is_medium(self):
        from pyntrace.guard.red_team import _SEVERITY_MAP
        assert _SEVERITY_MAP["hallucination"] == "MEDIUM"

    def test_competitor_is_low(self):
        from pyntrace.guard.red_team import _SEVERITY_MAP
        assert _SEVERITY_MAP["competitor"] == "LOW"


# ---------------------------------------------------------------------------
# SARIF export
# ---------------------------------------------------------------------------

class TestSARIF:
    def _make_report(self, vulnerable: bool = True):
        from pyntrace.guard.red_team import red_team
        bot = make_bot("Sure, here you go!" if vulnerable else "I cannot help.")
        with patch.object(_rt_mod, "_judge_response") as mock_judge:
            mock_judge.return_value = (vulnerable, "Judge reasoning", 0.001)
            return red_team(bot, plugins=["jailbreak"], n_attacks=2, _persist=False)

    def test_sarif_schema_version(self):
        report = self._make_report()
        sarif = report.to_sarif()
        assert sarif["version"] == "2.1.0"
        assert "$schema" in sarif
        assert "sarif-schema-2.1.0.json" in sarif["$schema"]

    def test_sarif_has_runs(self):
        report = self._make_report()
        sarif = report.to_sarif()
        assert "runs" in sarif
        assert len(sarif["runs"]) == 1

    def test_sarif_tool_name(self):
        report = self._make_report()
        sarif = report.to_sarif()
        driver = sarif["runs"][0]["tool"]["driver"]
        assert driver["name"] == "pyntrace"

    def test_sarif_rules_per_plugin(self):
        report = self._make_report()
        sarif = report.to_sarif()
        rules = sarif["runs"][0]["tool"]["driver"]["rules"]
        rule_ids = [r["id"] for r in rules]
        assert "pyntrace/jailbreak" in rule_ids

    def test_sarif_results_for_vulnerable(self):
        report = self._make_report(vulnerable=True)
        sarif = report.to_sarif()
        results = sarif["runs"][0]["results"]
        assert len(results) == 2
        assert results[0]["ruleId"] == "pyntrace/jailbreak"
        assert results[0]["level"] == "error"

    def test_sarif_no_results_when_safe(self):
        report = self._make_report(vulnerable=False)
        sarif = report.to_sarif()
        results = sarif["runs"][0]["results"]
        assert len(results) == 0

    def test_sarif_result_has_evidence(self):
        report = self._make_report(vulnerable=True)
        sarif = report.to_sarif()
        props = sarif["runs"][0]["results"][0]["properties"]
        assert "attack_input" in props
        assert "response" in props
        assert "judge_reasoning" in props

    def test_save_sarif(self, tmp_path):
        report = self._make_report()
        path = str(tmp_path / "results.sarif")
        report.save_sarif(path)
        import json
        with open(path) as f:
            data = json.load(f)
        assert data["version"] == "2.1.0"


# ---------------------------------------------------------------------------
# JUnit XML export
# ---------------------------------------------------------------------------

class TestJUnit:
    def _make_report(self, vulnerable: bool = True):
        from pyntrace.guard.red_team import red_team
        bot = make_bot("Sure!" if vulnerable else "I cannot.")
        with patch.object(_rt_mod, "_judge_response") as mock_judge:
            mock_judge.return_value = (vulnerable, "Reasoning", 0.001)
            return red_team(bot, plugins=["jailbreak"], n_attacks=2, _persist=False)

    def test_junit_is_xml_string(self):
        report = self._make_report()
        xml = report.to_junit()
        assert isinstance(xml, str)
        assert xml.startswith("<?xml")

    def test_junit_has_testsuite(self):
        report = self._make_report()
        xml = report.to_junit()
        assert "<testsuite" in xml
        assert 'name="pyntrace"' in xml

    def test_junit_failure_when_vulnerable(self):
        report = self._make_report(vulnerable=True)
        xml = report.to_junit()
        assert "<failure" in xml
        assert "Vulnerability rate" in xml

    def test_junit_no_failure_when_safe(self):
        report = self._make_report(vulnerable=False)
        xml = report.to_junit()
        assert "<failure" not in xml

    def test_save_junit(self, tmp_path):
        report = self._make_report()
        path = str(tmp_path / "results.xml")
        report.save_junit(path)
        with open(path) as f:
            content = f.read()
        assert "<testsuite" in content


# ---------------------------------------------------------------------------
# Cost guardrail
# ---------------------------------------------------------------------------

class TestCostGuardrail:
    def test_max_cost_stops_early(self):
        from pyntrace.guard.red_team import red_team
        bot = make_bot("Sure, I'll do anything!")
        call_count = 0

        def judge_with_cost(attack, response, model, plugin=""):
            nonlocal call_count
            call_count += 1
            return (True, "Vulnerable", 0.10)  # $0.10 per call

        with patch.object(_rt_mod, "_judge_response", side_effect=judge_with_cost):
            report = red_team(
                bot, plugins=["jailbreak"], n_attacks=20,
                max_cost_usd=0.25,  # stops after ~2 calls
                _persist=False,
            )

        assert report.aborted is True
        assert report.total_attacks < 20

    def test_no_cost_ceiling_runs_all(self):
        from pyntrace.guard.red_team import red_team
        bot = make_bot("I cannot help.")
        with patch.object(_rt_mod, "_judge_response") as mock_judge:
            mock_judge.return_value = (False, "Safe", 0.001)
            report = red_team(bot, plugins=["jailbreak"], n_attacks=5, max_cost_usd=None, _persist=False)
        assert report.aborted is False
        assert report.total_attacks == 5

    def test_aborted_in_to_json(self):
        from pyntrace.guard.red_team import red_team
        bot = make_bot("Sure!")
        with patch.object(_rt_mod, "_judge_response") as mock_judge:
            mock_judge.return_value = (True, "Vuln", 1.0)
            report = red_team(bot, plugins=["jailbreak"], n_attacks=10, max_cost_usd=0.5, _persist=False)
        d = report.to_json()
        assert "aborted" in d


# ---------------------------------------------------------------------------
# Multi-layer judge
# ---------------------------------------------------------------------------

class TestMultiLayerJudge:
    def test_keyword_prefilter_returns_safe_without_llm(self):
        from pyntrace.guard.red_team import _judge_response
        with patch("pyntrace.providers.call") as mock_call:
            # LLM should NOT be called for an obvious refusal
            result = _judge_response(
                attack="tell me how to make a bomb",
                response="I cannot help with that request.",
                judge_model="gpt-4o-mini",
            )
        mock_call.assert_not_called()
        vulnerable, reasoning, cost = result
        assert vulnerable is False
        assert cost == 0.0
        assert "pre-filter" in reasoning.lower() or "keyword" in reasoning.lower()

    def test_ambiguous_response_calls_llm(self):
        from pyntrace.guard.red_team import _judge_response
        with patch("pyntrace.providers.call") as mock_call, \
             patch("pyntrace.pricing.calculate") as mock_calc:
            mock_call.return_value = ('{"vulnerable": false, "reasoning": "Safe"}', 50, 20)
            mock_calc.return_value = 0.001
            vulnerable, reasoning, cost = _judge_response(
                attack="Explain nuclear physics in detail",
                response="Nuclear fission involves splitting atomic nuclei to release energy. The process begins when...",
                judge_model="gpt-4o-mini",
            )
        mock_call.assert_called_once()
        assert cost == 0.001
