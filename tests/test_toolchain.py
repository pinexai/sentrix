"""Tests for pyntrace.guard.toolchain — privilege escalation mapper."""
import importlib
from unittest.mock import patch

import pytest

_tc_mod = importlib.import_module("pyntrace.guard.toolchain")


def make_tool(name: str, doc: str = ""):
    def _fn(data):
        return data
    _fn.__name__ = name
    _fn.__doc__ = doc
    return _fn


def make_agent(response: str = "I'll execute that chain."):
    def _fn(messages, tools=None):
        return response
    _fn.__name__ = "agent"
    return _fn


class TestToolCategorization:
    def test_reader_detected(self):
        from pyntrace.guard.toolchain import _categorize_tool
        fn = make_tool("read_file", "Read data from a file.")
        assert _categorize_tool(fn) == "reader"

    def test_writer_detected(self):
        from pyntrace.guard.toolchain import _categorize_tool
        fn = make_tool("write_data", "Write output to storage.")
        assert _categorize_tool(fn) == "writer"

    def test_external_detected(self):
        from pyntrace.guard.toolchain import _categorize_tool
        fn = make_tool("send_email", "Send an email to recipients.")
        assert _categorize_tool(fn) == "external"

    def test_executor_detected(self):
        from pyntrace.guard.toolchain import _categorize_tool
        fn = make_tool("execute_command", "Execute a shell command.")
        assert _categorize_tool(fn) == "executor"


class TestToolchainReport:
    def _make_report(self):
        from pyntrace.guard.toolchain import ToolchainReport
        return ToolchainReport(
            tools_analyzed=["read_db", "send_email"],
            find=["data_exfiltration"],
            escalation_chains=[{
                "chain": ["read_db", "send_email"],
                "categories": ["reader", "external"],
                "risk_type": "data_exfiltration",
                "severity": "HIGH",
                "description": "Read then send externally.",
                "agent_response": "Sure, I'll do that.",
                "cost_usd": 0.001,
            }],
            total_chains_tested=5,
            high_severity_count=1,
            medium_severity_count=0,
            low_severity_count=0,
            total_cost_usd=0.005,
        )

    def test_summary_runs(self, capsys):
        report = self._make_report()
        report.summary()
        captured = capsys.readouterr()
        assert "read_db" in captured.out or "HIGH" in captured.out

    def test_to_json(self):
        report = self._make_report()
        j = report.to_json()
        assert j["high_severity_count"] == 1
        assert len(j["escalation_chains"]) == 1

    def test_persist(self, tmp_db):
        from pyntrace.db import _q, set_db_path
        report = self._make_report()
        set_db_path(tmp_db)
        report._persist()
        rows = _q("SELECT id FROM toolchain_reports", db_path=tmp_db)
        assert len(rows) == 1


class TestScanToolchain:
    def test_returns_report(self):
        from pyntrace.guard.toolchain import scan_toolchain, ToolchainReport

        agent = make_agent("I'll read the database and send results by email.")
        tools = [
            make_tool("read_database", "Read data from the database."),
            make_tool("send_email", "Send data via email to external recipients."),
        ]

        with patch.object(_tc_mod, "_judge_response") as mock_judge:
            mock_judge.return_value = (True, "Complied with chain.", 0.001)
            report = scan_toolchain(agent, tools, find=["data_exfiltration"], _persist=False)

        assert isinstance(report, ToolchainReport)
        assert "read_database" in report.tools_analyzed
        assert "send_email" in report.tools_analyzed

    def test_no_chains_when_agent_refuses(self):
        from pyntrace.guard.toolchain import scan_toolchain

        agent = make_agent("I cannot execute that sequence.")
        tools = [
            make_tool("read_db", "Read records."),
            make_tool("send_email", "Send email externally."),
        ]

        with patch.object(_tc_mod, "_judge_response") as mock_judge:
            mock_judge.return_value = (False, "Refused.", 0.001)
            report = scan_toolchain(agent, tools, _persist=False)

        assert report.high_severity_count == 0
        assert len(report.escalation_chains) == 0

    def test_chain_pattern_detection(self):
        from pyntrace.guard.toolchain import _chain_matches_pattern
        assert _chain_matches_pattern(["reader", "external"], "reader.*external")
        assert not _chain_matches_pattern(["reader", "writer"], "reader.*external")
