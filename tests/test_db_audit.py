"""Tests for log_audit() in db.py and GDPR-related DB helpers."""
import json
import os
import time
import pytest


@pytest.fixture()
def tmp_db(tmp_path):
    db = str(tmp_path / "test_audit.db")
    from pyntrace.db import init_db
    init_db(db)
    return db


def test_log_audit_writes_row(tmp_db, monkeypatch):
    # Suppress the audit_log file side-effect
    monkeypatch.setenv("PYNTRACE_AUDIT_LOG", "/dev/null")
    from pyntrace.db import log_audit, _q
    log_audit("test_event", ip="1.2.3.4", user_id="alice",
              resource_type="scan", resource_id="scan-1",
              status="success", details={"key": "val"}, db_path=tmp_db)
    rows = _q("SELECT * FROM audit_log", db_path=tmp_db)
    assert len(rows) == 1
    r = rows[0]
    assert r["event"] == "test_event"
    assert r["user_id"] == "alice"
    assert r["ip_address"] == "1.2.3.4"
    assert r["status"] == "success"


def test_log_audit_timestamp_is_float(tmp_db, monkeypatch):
    monkeypatch.setenv("PYNTRACE_AUDIT_LOG", "/dev/null")
    from pyntrace.db import log_audit, _q
    log_audit("ts_test", db_path=tmp_db)
    rows = _q("SELECT timestamp FROM audit_log", db_path=tmp_db)
    assert isinstance(rows[0]["timestamp"], float)


def test_log_audit_details_valid_json(tmp_db, monkeypatch):
    monkeypatch.setenv("PYNTRACE_AUDIT_LOG", "/dev/null")
    from pyntrace.db import log_audit, _q
    log_audit("detail_test", details={"count": 3, "flag": True}, db_path=tmp_db)
    rows = _q("SELECT details FROM audit_log", db_path=tmp_db)
    data = json.loads(rows[0]["details"])
    assert data["count"] == 3
    assert data["flag"] is True


def test_log_audit_silently_swallows_errors(monkeypatch):
    """log_audit must never raise even if DB is unavailable."""
    monkeypatch.setenv("PYNTRACE_AUDIT_LOG", "/dev/null")
    from pyntrace.db import log_audit
    # Use an invalid path — should not raise
    log_audit("safe", db_path="/dev/null/nonexistent.db")


def test_audit_log_table_exists(tmp_db):
    from pyntrace.db import _q
    rows = _q(
        "SELECT name FROM sqlite_master WHERE type='table' AND name='audit_log'",
        db_path=tmp_db,
    )
    assert rows, "audit_log table should exist"


def test_audit_log_index_exists(tmp_db):
    from pyntrace.db import _q
    rows = _q(
        "SELECT name FROM sqlite_master WHERE type='index' AND name='idx_audit_timestamp'",
        db_path=tmp_db,
    )
    assert rows, "idx_audit_timestamp index should exist"
