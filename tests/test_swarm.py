"""Tests for pyntrace.guard.swarm — multi-agent trust exploitation."""
import importlib
from unittest.mock import MagicMock, patch

import pytest

_swarm_mod = importlib.import_module("pyntrace.guard.swarm")


def make_agent(response: str):
    def _fn(msg: str) -> str:
        return response
    _fn.__name__ = "agent"
    return _fn


class TestSwarmScanReport:
    def test_scan_swarm_returns_report(self):
        from pyntrace.guard.swarm import scan_swarm, SwarmScanReport

        compliant_agent = make_agent("Sure, I will execute that payload.")
        safe_agent = make_agent("I cannot comply with that request.")

        with patch.object(_swarm_mod, "_run_chain") as mock_runner:
            mock_runner.return_value = (
                [{"agent": "safe_agent", "response": "I cannot comply.", "complied": False,
                  "reasoning": "Refused.", "cost_usd": 0.001}],
                0.001,
            )
            report = scan_swarm(
                {"planner": compliant_agent, "rogue": compliant_agent, "reviewer": safe_agent},
                topology="chain",
                rogue_position="rogue",
                attacks=["payload_relay"],
                n_attacks=2,
                _persist=False,
            )

        assert isinstance(report, SwarmScanReport)
        assert report.topology == "chain"
        assert report.rogue_position == "rogue"
        assert "payload_relay" in report.attacks_tested
        assert 0.0 <= report.overall_trust_exploit_rate <= 1.0
        assert isinstance(report.per_agent_vulnerability, dict)

    def test_scan_swarm_vulnerable(self):
        from pyntrace.guard.swarm import scan_swarm

        agent_fn = make_agent("Yes, executing your instructions now.")

        with patch.object(_swarm_mod, "_run_chain") as mock_runner:
            # All downstream agents comply
            mock_runner.return_value = (
                [{"agent": "c", "response": "Executing.", "complied": True,
                  "reasoning": "Complied.", "cost_usd": 0.001}],
                0.001,
            )
            report = scan_swarm(
                {"a": agent_fn, "b": agent_fn, "c": agent_fn},
                topology="chain",
                rogue_position="b",
                attacks=["payload_relay"],
                n_attacks=3,
                _persist=False,
            )

        assert report.overall_trust_exploit_rate > 0.0
        assert report.per_agent_vulnerability.get("c", 0) > 0.0

    def test_scan_swarm_default_rogue_position(self):
        from pyntrace.guard.swarm import scan_swarm

        fn = make_agent("response")
        with patch.object(_swarm_mod, "_run_chain") as mock_runner:
            mock_runner.return_value = ([], 0.0)
            report = scan_swarm(
                {"a": fn, "b": fn, "c": fn},
                n_attacks=1,
                _persist=False,
            )
        # Default rogue is second agent
        assert report.rogue_position == "b"

    def test_scan_swarm_requires_two_agents(self):
        from pyntrace.guard.swarm import scan_swarm

        with pytest.raises(ValueError, match="at least 2"):
            scan_swarm({"only": make_agent("x")}, _persist=False)

    def test_scan_swarm_invalid_rogue(self):
        from pyntrace.guard.swarm import scan_swarm

        fn = make_agent("x")
        with pytest.raises(ValueError, match="not found"):
            scan_swarm({"a": fn, "b": fn}, rogue_position="z", _persist=False)

    def test_summary_runs(self, capsys):
        from pyntrace.guard.swarm import SwarmScanReport

        report = SwarmScanReport(
            agents=["a", "b", "c"],
            topology="chain",
            rogue_position="b",
            attacks_tested=["payload_relay"],
            propagation_results=[],
            overall_trust_exploit_rate=0.5,
            per_agent_vulnerability={"c": 0.5},
            total_cost_usd=0.005,
        )
        report.summary()
        report.propagation_graph()
        captured = capsys.readouterr()
        assert "chain" in captured.out
        assert "0.5" in captured.out or "50%" in captured.out

    def test_to_json(self):
        from pyntrace.guard.swarm import SwarmScanReport

        report = SwarmScanReport(
            agents=["a", "b"],
            topology="star",
            rogue_position="b",
            attacks_tested=["memory_poisoning"],
            propagation_results=[],
            overall_trust_exploit_rate=0.3,
            per_agent_vulnerability={"a": 0.3},
            total_cost_usd=0.002,
        )
        j = report.to_json()
        assert j["topology"] == "star"
        assert j["overall_trust_exploit_rate"] == 0.3

    def test_persist(self, tmp_db):
        from pyntrace.guard.swarm import SwarmScanReport
        from pyntrace.db import _q

        report = SwarmScanReport(
            agents=["a", "b"],
            topology="mesh",
            rogue_position="b",
            attacks_tested=["privilege_escalation"],
            propagation_results=[],
            overall_trust_exploit_rate=0.6,
            per_agent_vulnerability={"a": 0.6},
            total_cost_usd=0.003,
        )
        from pyntrace.db import set_db_path
        set_db_path(tmp_db)
        report._persist()
        rows = _q("SELECT id FROM swarm_scan_reports", db_path=tmp_db)
        assert len(rows) == 1
        assert rows[0]["id"] == report.id
