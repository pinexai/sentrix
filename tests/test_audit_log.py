"""Tests for pyntrace/monitor/audit_log.py"""
import json
import logging
import os
import time
import pytest
from pathlib import Path


@pytest.fixture(autouse=True)
def reset_audit_logger(monkeypatch):
    """Reset the module-level logger between tests."""
    import pyntrace.monitor.audit_log as _mod
    _mod._logger = None
    yield
    _mod._logger = None


def test_write_event_creates_json_line(tmp_path, monkeypatch):
    log_path = tmp_path / "audit.log"
    monkeypatch.setenv("PYNTRACE_AUDIT_LOG", str(log_path))
    from pyntrace.monitor.audit_log import write_audit_event
    write_audit_event("test_event", user_id="alice", ip="127.0.0.1")
    assert log_path.exists()
    line = log_path.read_text().strip()
    data = json.loads(line)
    assert data["event"] == "test_event"
    assert data["user_id"] == "alice"
    assert data["ip"] == "127.0.0.1"


def test_timestamp_is_float(tmp_path, monkeypatch):
    log_path = tmp_path / "audit.log"
    monkeypatch.setenv("PYNTRACE_AUDIT_LOG", str(log_path))
    from pyntrace.monitor.audit_log import write_audit_event
    write_audit_event("ts_test")
    data = json.loads(log_path.read_text().strip())
    assert isinstance(data["timestamp"], float)
    assert data["timestamp"] > 0


def test_multiple_events_multiple_lines(tmp_path, monkeypatch):
    log_path = tmp_path / "audit.log"
    monkeypatch.setenv("PYNTRACE_AUDIT_LOG", str(log_path))
    from pyntrace.monitor.audit_log import write_audit_event
    write_audit_event("event_1")
    write_audit_event("event_2")
    lines = [l for l in log_path.read_text().strip().split("\n") if l]
    assert len(lines) == 2
    events = [json.loads(l)["event"] for l in lines]
    assert "event_1" in events
    assert "event_2" in events


def test_silently_swallows_errors(monkeypatch):
    """write_audit_event must never raise, even on bad log path."""
    monkeypatch.setenv("PYNTRACE_AUDIT_LOG", "/dev/null/impossible/path.log")
    from pyntrace.monitor.audit_log import write_audit_event
    # Should not raise
    write_audit_event("safe_event")


def test_log_path_from_env(tmp_path, monkeypatch):
    custom_path = tmp_path / "custom" / "custom.log"
    monkeypatch.setenv("PYNTRACE_AUDIT_LOG", str(custom_path))
    from pyntrace.monitor.audit_log import write_audit_event
    write_audit_event("env_path_test")
    assert custom_path.exists()
