"""pyntrace Prometheus metrics exporter — zero required dependencies."""
from __future__ import annotations

import json
import threading
import time
from http.server import BaseHTTPRequestHandler, HTTPServer
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    pass


def _label(key: str, value: str) -> str:
    """Escape label value for Prometheus text format."""
    return value.replace("\\", "\\\\").replace('"', '\\"').replace("\n", "\\n")


def _metric(name: str, labels: dict, value: float, comment: str = "", mtype: str = "gauge") -> str:
    """Produce one Prometheus text-format metric line (with optional HELP/TYPE header)."""
    lstr = ",".join(f'{k}="{_label(k, str(v))}"' for k, v in labels.items())
    lpart = "{" + lstr + "}" if lstr else ""
    return f"{name}{lpart} {value}"


class PrometheusExporter:
    """
    Exports pyntrace SQLite data in Prometheus text format.

    Usage (standalone)::

        from pyntrace.monitor.prometheus import PrometheusExporter

        exp = PrometheusExporter(port=9090)
        exp.start()  # background HTTP server on /metrics

    Usage (FastAPI)::

        from pyntrace.monitor.prometheus import expose_metrics
        expose_metrics(app)  # adds GET /metrics to existing FastAPI app

    Usage (text only)::

        print(exp.get_metrics_text())
    """

    def __init__(self, port: int = 9090, db_path: str | None = None) -> None:
        self._port = port
        self._db_path = db_path
        self._server: HTTPServer | None = None

    def get_metrics_text(self) -> str:
        """Return all metrics in Prometheus text exposition format."""
        lines: list[str] = []

        try:
            from pyntrace.db import _q as q

            # ── Red team scans ──────────────────────────────────────────────
            lines.append("# HELP pyntrace_scans_total Total red team scans run")
            lines.append("# TYPE pyntrace_scans_total counter")
            rows = q(
                "SELECT model, COUNT(*) as cnt FROM red_team_reports GROUP BY model",
                db_path=self._db_path,
            )
            for r in rows:
                lines.append(_metric("pyntrace_scans_total", {"model": r["model"] or "unknown"}, r["cnt"]))

            lines.append("# HELP pyntrace_vulnerability_rate_avg Average vulnerability rate per model")
            lines.append("# TYPE pyntrace_vulnerability_rate_avg gauge")
            rows = q(
                "SELECT model, AVG(vulnerability_rate) as avg_rate FROM red_team_reports GROUP BY model",
                db_path=self._db_path,
            )
            for r in rows:
                lines.append(_metric("pyntrace_vulnerability_rate_avg", {"model": r["model"] or "unknown"}, round(r["avg_rate"] or 0, 4)))

            # ── Costs ───────────────────────────────────────────────────────
            lines.append("# HELP pyntrace_cost_usd_total Total LLM cost in USD")
            lines.append("# TYPE pyntrace_cost_usd_total counter")
            rows = q(
                "SELECT model, SUM(cost_usd) as total FROM llm_calls GROUP BY model",
                db_path=self._db_path,
            )
            for r in rows:
                lines.append(_metric("pyntrace_cost_usd_total", {"model": r["model"] or "unknown"}, round(r["total"] or 0, 6)))

            lines.append("# HELP pyntrace_llm_calls_total Total LLM API calls")
            lines.append("# TYPE pyntrace_llm_calls_total counter")
            rows = q(
                "SELECT model, COUNT(*) as cnt FROM llm_calls GROUP BY model",
                db_path=self._db_path,
            )
            for r in rows:
                lines.append(_metric("pyntrace_llm_calls_total", {"model": r["model"] or "unknown"}, r["cnt"]))

            lines.append("# HELP pyntrace_llm_latency_ms_avg Average LLM call latency in ms")
            lines.append("# TYPE pyntrace_llm_latency_ms_avg gauge")
            rows = q(
                "SELECT model, AVG(duration_ms) as avg_ms FROM llm_calls GROUP BY model",
                db_path=self._db_path,
            )
            for r in rows:
                lines.append(_metric("pyntrace_llm_latency_ms_avg", {"model": r["model"] or "unknown"}, round(r["avg_ms"] or 0, 2)))

            # ── Traces ──────────────────────────────────────────────────────
            lines.append("# HELP pyntrace_traces_total Total production traces recorded")
            lines.append("# TYPE pyntrace_traces_total counter")
            rows = q("SELECT COUNT(*) as cnt FROM traces", db_path=self._db_path)
            if rows:
                lines.append(_metric("pyntrace_traces_total", {}, rows[0]["cnt"]))

            lines.append("# HELP pyntrace_trace_errors_total Total traces with errors")
            lines.append("# TYPE pyntrace_trace_errors_total counter")
            rows = q("SELECT COUNT(*) as cnt FROM traces WHERE error IS NOT NULL AND error != ''", db_path=self._db_path)
            if rows:
                lines.append(_metric("pyntrace_trace_errors_total", {}, rows[0]["cnt"]))

            # ── MCP scans ───────────────────────────────────────────────────
            lines.append("# HELP pyntrace_mcp_scans_total Total MCP security scans run")
            lines.append("# TYPE pyntrace_mcp_scans_total counter")
            rows = q("SELECT COUNT(*) as cnt FROM mcp_scan_reports", db_path=self._db_path)
            if rows:
                lines.append(_metric("pyntrace_mcp_scans_total", {}, rows[0]["cnt"]))

            lines.append("# HELP pyntrace_mcp_vulnerabilities_total Total MCP vulnerabilities found")
            lines.append("# TYPE pyntrace_mcp_vulnerabilities_total counter")
            rows = q("SELECT SUM(vulnerable_count) as total FROM mcp_scan_reports", db_path=self._db_path)
            if rows and rows[0]["total"] is not None:
                lines.append(_metric("pyntrace_mcp_vulnerabilities_total", {}, rows[0]["total"]))

            # ── Latency reports ─────────────────────────────────────────────
            lines.append("# HELP pyntrace_latency_p95_ms p95 response latency from benchmark runs")
            lines.append("# TYPE pyntrace_latency_p95_ms gauge")
            rows = q(
                "SELECT fn_name, p95_ms FROM latency_reports ORDER BY created_at DESC LIMIT 50",
                db_path=self._db_path,
            )
            for r in rows:
                lines.append(_metric("pyntrace_latency_p95_ms", {"fn": r["fn_name"] or "unknown"}, round(r["p95_ms"] or 0, 2)))

        except Exception:
            lines.append("# pyntrace: database not initialised yet")

        lines.append(f"\n# Generated at {time.time()}")
        return "\n".join(lines) + "\n"

    def start(self) -> None:
        """Start a background HTTP server on /metrics."""
        exporter = self

        class Handler(BaseHTTPRequestHandler):
            def do_GET(self):
                if self.path in ("/metrics", "/metrics/"):
                    body = exporter.get_metrics_text().encode()
                    self.send_response(200)
                    self.send_header("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
                    self.send_header("Content-Length", str(len(body)))
                    self.end_headers()
                    self.wfile.write(body)
                else:
                    self.send_response(404)
                    self.end_headers()

            def log_message(self, *args):  # suppress access logs
                pass

        self._server = HTTPServer(("0.0.0.0", self._port), Handler)
        t = threading.Thread(target=self._server.serve_forever, daemon=True)
        t.start()
        print(f"[pyntrace] Prometheus metrics available at http://localhost:{self._port}/metrics")

    def stop(self) -> None:
        if self._server:
            self._server.shutdown()


def expose_metrics(app: "object", db_path: str | None = None) -> None:
    """
    Add a GET /metrics route to an existing FastAPI app.

    Usage::

        from pyntrace.monitor.prometheus import expose_metrics
        expose_metrics(app)
    """
    try:
        from fastapi import Response

        exporter = PrometheusExporter(db_path=db_path)

        @app.get("/metrics", include_in_schema=False)  # type: ignore[attr-defined]
        async def metrics_endpoint():
            return Response(
                content=exporter.get_metrics_text(),
                media_type="text/plain; version=0.0.4; charset=utf-8",
            )
    except ImportError:
        pass
