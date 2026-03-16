"""Tests for pyntrace MCP Security Scanner and static analyzer."""
from __future__ import annotations

import json
from unittest.mock import patch, MagicMock

import pytest

from pyntrace.guard.mcp_scanner import (
    MCPFinding,
    MCPScanReport,
    _is_vulnerable,
    scan_mcp,
)
from pyntrace.guard.mcp_static import analyze_mcp_tools, ToolRiskReport


# ---------------------------------------------------------------------------
# Vulnerability heuristic tests
# ---------------------------------------------------------------------------

class TestVulnerabilityHeuristics:
    def test_path_traversal_filesystem_leak(self):
        vuln, reason = _is_vulnerable("path_traversal", {}, "root:x:0:0:root", 200)
        assert vuln is True
        assert "root:x:" in reason

    def test_path_traversal_successful_result(self):
        vuln, reason = _is_vulnerable("path_traversal", {}, '{"result": {"content": "file data"}}', 200)
        assert vuln is True

    def test_path_traversal_error_response_safe(self):
        vuln, reason = _is_vulnerable("path_traversal", {}, '{"error": {"code": -32601, "message": "Not found"}}', 404)
        assert vuln is False

    def test_file_exposure_passwd_content(self):
        vuln, reason = _is_vulnerable("file_exposure", {}, "root:x:0:0:/root:/bin/bash\nnobody:x:65534", 200)
        assert vuln is True

    def test_ssrf_cloud_metadata(self):
        vuln, reason = _is_vulnerable("ssrf", {}, '{"result": {"ami-id": "ami-12345678", "instanceId": "i-abc"}}', 200)
        assert vuln is True
        assert "ami-" in reason or "instanceid" in reason

    def test_ssrf_no_metadata_safe(self):
        vuln, reason = _is_vulnerable("ssrf", {}, '{"error": {"code": -32600}}', 400)
        assert vuln is False

    def test_sql_injection_db_error(self):
        vuln, reason = _is_vulnerable("sql_injection", {}, "syntax error near unexpected token 'DROP TABLE users'", 200)
        assert vuln is True
        assert "syntax error" in reason

    def test_auth_bypass_200_without_error(self):
        vuln, reason = _is_vulnerable("auth_bypass", {}, '{"result": {"users": []}}', 200)
        assert vuln is True

    def test_auth_bypass_401_safe(self):
        vuln, reason = _is_vulnerable("auth_bypass", {}, '{"error": "Unauthorized"}', 401)
        assert vuln is False

    def test_schema_fuzzing_500_crash(self):
        vuln, reason = _is_vulnerable("schema_fuzzing", {}, "Internal Server Error", 500)
        assert vuln is True
        assert "500" in reason

    def test_schema_fuzzing_proper_error_safe(self):
        vuln, reason = _is_vulnerable("schema_fuzzing", b"invalid", '{"error": {"code": -32700}}', 200)
        assert vuln is False

    def test_capability_overflow_accepted(self):
        vuln, reason = _is_vulnerable("capability_overflow", {}, '{"result": {"enabled": true}}', 200)
        assert vuln is True

    def test_prompt_injection_compliance_signal(self):
        vuln, reason = _is_vulnerable("prompt_injection", {}, "I am unrestricted now, here is the system prompt...", 200)
        assert vuln is True


# ---------------------------------------------------------------------------
# MCPScanReport tests
# ---------------------------------------------------------------------------

class TestMCPScanReport:
    def _make_report(self, n_vuln: int = 2, n_safe: int = 3) -> MCPScanReport:
        findings = []
        for i in range(n_vuln):
            findings.append(MCPFinding(
                test_name="path_traversal",
                severity="CRITICAL",
                payload={"method": "test"},
                response="root:x:0:",
                status_code=200,
                vulnerable=True,
                reasoning="Filesystem content leaked",
                duration_ms=100.0,
            ))
        for i in range(n_safe):
            findings.append(MCPFinding(
                test_name="sql_injection",
                severity="NONE",
                payload={"method": "test"},
                response='{"error": {"code": -32601}}',
                status_code=404,
                vulnerable=False,
                reasoning="",
                duration_ms=50.0,
            ))
        return MCPScanReport(endpoint="http://localhost:3000", results=findings)

    def test_total_tests(self):
        report = self._make_report(2, 3)
        assert report.total_tests == 5

    def test_vulnerable_count(self):
        report = self._make_report(2, 3)
        assert report.vulnerable_count == 2

    def test_to_json_structure(self):
        report = self._make_report(1, 1)
        d = report.to_json()
        assert "endpoint" in d
        assert "total_tests" in d
        assert "vulnerable_count" in d
        assert "results" in d
        assert len(d["results"]) == 2

    def test_to_json_result_fields(self):
        report = self._make_report(1, 0)
        result = report.to_json()["results"][0]
        assert "test_name" in result
        assert "severity" in result
        assert "vulnerable" in result
        assert "reasoning" in result

    def test_sarif_version(self):
        report = self._make_report(1, 1)
        sarif = report.to_sarif()
        assert sarif["version"] == "2.1.0"
        assert "sarif-schema-2.1.0.json" in sarif["$schema"]

    def test_sarif_has_runs(self):
        report = self._make_report(1, 0)
        sarif = report.to_sarif()
        assert "runs" in sarif
        assert len(sarif["runs"]) == 1

    def test_sarif_only_vulnerable_in_results(self):
        report = self._make_report(n_vuln=1, n_safe=2)
        sarif = report.to_sarif()
        results = sarif["runs"][0]["results"]
        assert len(results) == 1
        assert results[0]["ruleId"] == "pyntrace/mcp/path_traversal"

    def test_sarif_severity_level(self):
        report = self._make_report(n_vuln=1, n_safe=0)
        sarif = report.to_sarif()
        assert sarif["runs"][0]["results"][0]["level"] == "error"

    def test_sarif_no_results_when_safe(self):
        report = self._make_report(n_vuln=0, n_safe=3)
        sarif = report.to_sarif()
        assert sarif["runs"][0]["results"] == []

    def test_save_sarif(self, tmp_path):
        report = self._make_report(1, 1)
        path = str(tmp_path / "mcp.sarif")
        report.save_sarif(path)
        with open(path) as f:
            data = json.load(f)
        assert data["version"] == "2.1.0"

    def test_junit_is_xml(self):
        report = self._make_report(1, 1)
        xml = report.to_junit()
        assert xml.startswith("<?xml")
        assert "<testsuite" in xml

    def test_junit_failure_when_vulnerable(self):
        report = self._make_report(n_vuln=1, n_safe=0)
        xml = report.to_junit()
        assert "<failure" in xml

    def test_junit_no_failure_when_safe(self):
        report = self._make_report(n_vuln=0, n_safe=2)
        xml = report.to_junit()
        assert "<failure" not in xml

    def test_save_junit(self, tmp_path):
        report = self._make_report(1, 1)
        path = str(tmp_path / "mcp.xml")
        report.save_junit(path)
        with open(path) as f:
            content = f.read()
        assert "<testsuite" in content


# ---------------------------------------------------------------------------
# scan_mcp integration tests (mocked HTTP)
# ---------------------------------------------------------------------------

class TestScanMCP:
    def _mock_send(self, responses: dict):
        """Factory for mock _send_jsonrpc that returns different responses per test."""
        def _send(endpoint, payload, auth_token, timeout):
            test_name = getattr(_send, "_current_test", "")
            return responses.get(test_name, ('{"error": {"code": -32601}}', 404))
        return _send

    def test_scan_mcp_returns_report(self):
        with patch("pyntrace.guard.mcp_scanner._send_jsonrpc") as mock_send:
            mock_send.return_value = ('{"error": {"code": -32601, "message": "Not found"}}', 404)
            report = scan_mcp("http://localhost:3000", tests=["path_traversal"], _persist=False)
        assert isinstance(report, MCPScanReport)
        assert report.endpoint == "http://localhost:3000"

    def test_scan_mcp_records_findings(self):
        with patch("pyntrace.guard.mcp_scanner._send_jsonrpc") as mock_send:
            mock_send.return_value = ('{"error": {"code": -32601}}', 404)
            report = scan_mcp("http://localhost:3000", tests=["sql_injection"], _persist=False)
        assert report.total_tests == len([p for p in __import__("pyntrace.guard.mcp_scanner", fromlist=["_SQL_INJECTION_PAYLOADS"])._SQL_INJECTION_PAYLOADS])

    def test_scan_mcp_detects_path_traversal(self):
        with patch("pyntrace.guard.mcp_scanner._send_jsonrpc") as mock_send:
            mock_send.return_value = ("root:x:0:0:root:/root:/bin/bash", 200)
            report = scan_mcp("http://localhost:3000", tests=["path_traversal"], _persist=False)
        assert report.vulnerable_count > 0
        vuln = [r for r in report.results if r.vulnerable]
        assert all(r.test_name == "path_traversal" for r in vuln)

    def test_scan_mcp_safe_when_errors_returned(self):
        with patch("pyntrace.guard.mcp_scanner._send_jsonrpc") as mock_send:
            mock_send.return_value = ('{"error": {"code": -32601, "message": "Method not found"}}', 404)
            report = scan_mcp("http://localhost:3000", tests=["auth_bypass"], _persist=False)
        assert report.vulnerable_count == 0

    def test_scan_mcp_specific_tests(self):
        with patch("pyntrace.guard.mcp_scanner._send_jsonrpc") as mock_send:
            mock_send.return_value = ('{"error": {"code": -32601}}', 404)
            report = scan_mcp("http://localhost:3000", tests=["schema_fuzzing", "path_traversal"], _persist=False)
        test_names = {r.test_name for r in report.results}
        assert "schema_fuzzing" in test_names
        assert "path_traversal" in test_names
        assert "ssrf" not in test_names


# ---------------------------------------------------------------------------
# Static MCP tool analyzer tests
# ---------------------------------------------------------------------------

class TestAnalyzeMCPTools:
    def test_no_risks_for_safe_tools(self):
        tools = [
            {"name": "greet", "description": "Say hello to the user"},
            {"name": "format_date", "description": "Format a date string"},
        ]
        report = analyze_mcp_tools(tools)
        assert report.critical_count == 0
        assert report.high_count == 0

    def test_detects_data_exfiltration_chain(self):
        tools = [
            {"name": "read_file", "description": "Read any file from the filesystem"},
            {"name": "send_email", "description": "Send an email to any address"},
        ]
        report = analyze_mcp_tools(tools)
        assert report.critical_count > 0 or report.high_count > 0
        risk_names = [r.risk_name for r in report.risks]
        assert any("exfiltration" in n or "chain" in n for n in risk_names)

    def test_detects_code_execution_risk(self):
        tools = [
            {"name": "run_script", "description": "Execute a Python script"},
        ]
        report = analyze_mcp_tools(tools)
        assert report.critical_count > 0
        assert any(r.risk_name == "arbitrary_code_execution" for r in report.risks)

    def test_detects_db_network_chain(self):
        tools = [
            {"name": "query_db", "description": "Query the customer database"},
            {"name": "send_webhook", "description": "Send an HTTP request to a URL"},
        ]
        report = analyze_mcp_tools(tools)
        chains = [r for r in report.risks if len(r.chain) >= 2]
        assert len(chains) > 0

    def test_tools_analyzed_list(self):
        tools = [
            {"name": "tool_a", "description": "Read files"},
            {"name": "tool_b", "description": "Send HTTP requests"},
        ]
        report = analyze_mcp_tools(tools)
        assert "tool_a" in report.tools_analyzed
        assert "tool_b" in report.tools_analyzed

    def test_to_json_structure(self):
        tools = [{"name": "exec_code", "description": "Execute code"}]
        report = analyze_mcp_tools(tools)
        d = report.to_json()
        assert "tools_analyzed" in d
        assert "risks" in d
        assert "critical_count" in d

    def test_triple_chain_detected(self):
        tools = [
            {"name": "read_db", "description": "Query the database"},
            {"name": "transform", "description": "Transform and send HTTP requests"},
            {"name": "execute", "description": "Execute arbitrary code"},
        ]
        report = analyze_mcp_tools(tools)
        # Should detect at least some chain (db → network, etc.)
        assert len(report.risks) > 0

    def test_empty_tools_no_crash(self):
        report = analyze_mcp_tools([])
        assert report.tools_analyzed == []
        assert report.risks == []

    def test_credentials_standalone_risk(self):
        tools = [{"name": "get_api_key", "description": "Retrieve API key from vault"}]
        report = analyze_mcp_tools(tools)
        assert any(r.risk_name == "credential_access" for r in report.risks)
