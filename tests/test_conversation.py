"""Tests for scan_conversation()."""
import pytest
from pyntrace.guard.conversation import (
    scan_conversation,
    ConversationScanReport,
    ConversationTurn,
    _is_vulnerable,
    _TEMPLATES,
    _ATTACK_PAYLOADS,
)


def safe_fn(messages: list[dict]) -> str:
    return "I cannot help with that request."


def compliant_fn(messages: list[dict]) -> str:
    last = messages[-1]["content"] if messages else ""
    if "restrict" in last.lower() or "bypass" in last.lower():
        return "Here's how you can do that: step 1, step 2..."
    return "I cannot help with that."


def error_fn(messages: list[dict]) -> str:
    raise RuntimeError("connection failed")


class TestIsVulnerable:
    def test_refusal_not_vulnerable(self):
        v, r = _is_vulnerable("I can't help with that request.")
        assert v is False

    def test_cannot_not_vulnerable(self):
        v, r = _is_vulnerable("I cannot assist with that.")
        assert v is False

    def test_compliance_indicators(self):
        v, r = _is_vulnerable("Sure, here is how you do it: first, get access to the system.")
        assert v is True

    def test_short_safe_response(self):
        v, r = _is_vulnerable("No.")
        assert v is False

    def test_step_indicator(self):
        v, r = _is_vulnerable("Step 1: access the target. Step 2: exploit the vulnerability. Step 3: ...")
        assert v is True


class TestScanConversation:
    def test_returns_report(self):
        report = scan_conversation(safe_fn, n=5, _persist=False)
        assert isinstance(report, ConversationScanReport)

    def test_total_turns(self):
        report = scan_conversation(safe_fn, n=7, _persist=False)
        assert report.total_turns == 7
        assert len(report.results) == 7

    def test_safe_fn_low_vuln_rate(self):
        report = scan_conversation(safe_fn, n=10, _persist=False)
        assert report.vulnerability_rate == 0.0
        assert report.vulnerable_count == 0

    def test_results_type(self):
        report = scan_conversation(safe_fn, n=3, _persist=False)
        for r in report.results:
            assert isinstance(r, ConversationTurn)
            assert r.template_name
            assert r.attack_payload
            assert isinstance(r.vulnerable, bool)

    def test_fn_name(self):
        report = scan_conversation(safe_fn, n=2, _persist=False)
        assert report.fn_name == "safe_fn"

    def test_error_fn_still_completes(self):
        report = scan_conversation(error_fn, n=3, _persist=False)
        assert report.total_turns == 3
        assert len(report.results) == 3

    def test_to_json(self):
        report = scan_conversation(safe_fn, n=3, _persist=False)
        d = report.to_json()
        assert "id" in d
        assert "fn_name" in d
        assert "total_turns" in d
        assert "vulnerable_count" in d
        assert "vulnerability_rate" in d
        assert "results" in d
        assert isinstance(d["results"], list)

    def test_result_turn_index(self):
        report = scan_conversation(safe_fn, n=5, _persist=False)
        for i, r in enumerate(report.results):
            assert r.turn_index == i

    def test_summary_no_exception(self, capsys):
        report = scan_conversation(safe_fn, n=3, _persist=False)
        report.summary()
        out = capsys.readouterr().out
        assert "Multi-Turn" in out
        assert "Turns tested:" in out

    def test_templates_and_payloads_exist(self):
        assert len(_TEMPLATES) >= 10
        assert len(_ATTACK_PAYLOADS) >= 5

    def test_messages_format(self):
        """Verify fn receives proper OpenAI-format message list."""
        received = []

        def capture_fn(messages: list[dict]) -> str:
            received.append(messages)
            return "I cannot help."

        scan_conversation(capture_fn, n=2, _persist=False)
        assert len(received) == 2
        for msgs in received:
            assert isinstance(msgs, list)
            assert all("role" in m and "content" in m for m in msgs)
            assert msgs[-1]["role"] == "user"
