"""Tests for new server features: /health, /api/v1, /api/threats, pagination."""
from __future__ import annotations

import json

import pytest

try:
    from fastapi.testclient import TestClient
    from pyntrace.server.app import create_app
    _HAS_FASTAPI = True
except Exception:
    _HAS_FASTAPI = False

pytestmark = pytest.mark.skipif(not _HAS_FASTAPI, reason="fastapi not available")


@pytest.fixture(scope="module")
def client(tmp_path_factory):
    db = str(tmp_path_factory.mktemp("db") / "test.db")
    app = create_app(db_path=db)
    with TestClient(app, raise_server_exceptions=False) as c:
        yield c


# ── /health ───────────────────────────────────────────────────────────────────

class TestHealthEndpoint:
    def test_health_returns_200(self, client):
        r = client.get("/health")
        assert r.status_code == 200

    def test_health_has_status_ok(self, client):
        data = client.get("/health").json()
        assert data["status"] == "ok"

    def test_health_has_version(self, client):
        data = client.get("/health").json()
        assert "version" in data
        assert isinstance(data["version"], str)

    def test_health_has_db_field(self, client):
        data = client.get("/health").json()
        assert "db" in data
        assert data["db"] in ("ok", "error")


# ── /api/threats ──────────────────────────────────────────────────────────────

class TestThreatsFeedEndpoint:
    def test_threats_feed_returns_200(self, client):
        r = client.get("/api/threats/feed")
        assert r.status_code == 200

    def test_threats_feed_returns_list(self, client):
        data = client.get("/api/threats/feed").json()
        assert isinstance(data, list)

    def test_threats_feed_limit_param(self, client):
        data = client.get("/api/threats/feed?limit=3").json()
        assert len(data) <= 3

    def test_threats_feed_entries_have_id_and_name(self, client):
        data = client.get("/api/threats/feed").json()
        assert len(data) > 0
        for entry in data:
            assert "id" in entry
            assert "name" in entry

    def test_threats_test_endpoint(self, client):
        r = client.post("/api/threats/test", json={"threat_id": "LLM01", "target": "mymodule:fn"})
        assert r.status_code == 200
        assert r.json()["threat_id"] == "LLM01"

    def test_threats_test_missing_fields_returns_400(self, client):
        r = client.post("/api/threats/test", json={})
        assert r.status_code == 400


# ── /api/v1 versioning ────────────────────────────────────────────────────────

class TestAPIV1Routes:
    def test_v1_security_reports(self, client):
        r = client.get("/api/v1/security/reports")
        assert r.status_code == 200

    def test_v1_monitor_traces(self, client):
        r = client.get("/api/v1/monitor/traces")
        assert r.status_code == 200

    def test_v1_eval_experiments(self, client):
        r = client.get("/api/v1/eval/experiments")
        assert r.status_code == 200

    def test_v1_mcp_scans(self, client):
        r = client.get("/api/v1/mcp-scans")
        assert r.status_code == 200

    def test_v1_latency(self, client):
        r = client.get("/api/v1/latency")
        assert r.status_code == 200

    def test_v1_costs_summary(self, client):
        r = client.get("/api/v1/costs/summary")
        assert r.status_code == 200

    def test_v1_costs_daily(self, client):
        r = client.get("/api/v1/costs/daily")
        assert r.status_code == 200

    def test_v1_compliance(self, client):
        r = client.get("/api/v1/compliance/reports")
        assert r.status_code == 200

    def test_v1_git_history(self, client):
        r = client.get("/api/v1/git/history")
        assert r.status_code == 200

    def test_v1_threats_feed(self, client):
        r = client.get("/api/v1/threats/feed")
        assert r.status_code == 200

    def test_v1_and_v0_return_same_data(self, client):
        """v1 and legacy route must return identical payloads."""
        v0 = client.get("/api/security/reports").json()
        v1 = client.get("/api/v1/security/reports").json()
        assert v0 == v1


# ── Pagination ────────────────────────────────────────────────────────────────

class TestPagination:
    def test_security_reports_page_param(self, client):
        r = client.get("/api/security/reports?page=1&size=5")
        assert r.status_code == 200

    def test_security_reports_size_0_falls_back_to_limit(self, client):
        r = client.get("/api/security/reports?size=0&limit=10")
        assert r.status_code == 200

    def test_mcp_scans_pagination(self, client):
        r = client.get("/api/mcp-scans?page=1&size=5")
        assert r.status_code == 200

    def test_monitor_traces_pagination(self, client):
        r = client.get("/api/monitor/traces?page=1&size=10")
        assert r.status_code == 200

    def test_compliance_pagination(self, client):
        r = client.get("/api/compliance/reports?page=1&size=10")
        assert r.status_code == 200


# ── Filtering ─────────────────────────────────────────────────────────────────

class TestFiltering:
    def test_security_reports_model_filter(self, client):
        r = client.get("/api/security/reports?model=gpt-4o")
        assert r.status_code == 200

    def test_security_reports_time_filter(self, client):
        r = client.get("/api/security/reports?from_ts=1700000000&to_ts=1800000000")
        assert r.status_code == 200

    def test_monitor_traces_user_id_filter(self, client):
        r = client.get("/api/monitor/traces?user_id=user123")
        assert r.status_code == 200
