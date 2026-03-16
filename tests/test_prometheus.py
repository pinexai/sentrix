"""Tests for PrometheusExporter."""
import pytest
from unittest.mock import patch, MagicMock
from pyntrace.monitor.prometheus import PrometheusExporter, _metric, _label


class TestLabel:
    def test_escapes_backslash(self):
        assert _label("k", "a\\b") == "a\\\\b"

    def test_escapes_quote(self):
        assert _label("k", 'a"b') == 'a\\"b'

    def test_escapes_newline(self):
        assert _label("k", "a\nb") == "a\\nb"

    def test_no_change_normal(self):
        assert _label("k", "gpt-4o-mini") == "gpt-4o-mini"


class TestMetricLine:
    def test_no_labels(self):
        line = _metric("pyntrace_scans_total", {}, 42)
        assert line == "pyntrace_scans_total 42"

    def test_with_label(self):
        line = _metric("pyntrace_scans_total", {"model": "gpt-4"}, 12)
        assert 'model="model"' in line or 'model="gpt-4"' in line
        assert "12" in line

    def test_value_in_output(self):
        line = _metric("pyntrace_cost_usd_total", {"model": "claude"}, 3.14)
        assert "3.14" in line


class TestPrometheusExporter:
    def test_get_metrics_text_no_db(self):
        exp = PrometheusExporter(db_path="/tmp/nonexistent_pyntrace_test.db")
        text = exp.get_metrics_text()
        # Should not raise — returns fallback comment when DB not found
        assert isinstance(text, str)
        assert "Generated at" in text

    def test_get_metrics_text_with_db(self, tmp_path):
        db_file = str(tmp_path / "test.db")
        from pyntrace.db import init_db
        init_db(db_file)

        exp = PrometheusExporter(db_path=db_file)
        text = exp.get_metrics_text()

        assert "pyntrace_scans_total" in text
        assert "pyntrace_cost_usd_total" in text
        assert "pyntrace_llm_calls_total" in text
        assert "pyntrace_traces_total" in text
        assert "pyntrace_latency_p95_ms" in text
        assert "Generated at" in text

    def test_help_and_type_headers(self, tmp_path):
        db_file = str(tmp_path / "test.db")
        from pyntrace.db import init_db
        init_db(db_file)

        exp = PrometheusExporter(db_path=db_file)
        text = exp.get_metrics_text()

        assert "# HELP pyntrace_scans_total" in text
        assert "# TYPE pyntrace_scans_total counter" in text
        assert "# HELP pyntrace_cost_usd_total" in text

    def test_metrics_text_with_data(self, tmp_path):
        db_file = str(tmp_path / "test.db")
        from pyntrace.db import init_db, get_conn
        init_db(db_file)

        # Insert a fake LLM call
        conn = get_conn(db_file)
        with conn:
            conn.execute(
                "INSERT INTO llm_calls (model, provider, cost_usd, duration_ms, timestamp) VALUES (?,?,?,?,?)",
                ("gpt-4o-mini", "openai", 0.001, 250.0, 1700000000.0),
            )
        conn.close()

        exp = PrometheusExporter(db_path=db_file)
        text = exp.get_metrics_text()

        assert "gpt-4o-mini" in text
        assert "pyntrace_llm_calls_total" in text

    def test_start_spawns_thread(self):
        exp = PrometheusExporter(port=19091)
        with patch("pyntrace.monitor.prometheus.HTTPServer") as mock_server_cls:
            mock_server = MagicMock()
            mock_server_cls.return_value = mock_server
            with patch("threading.Thread") as mock_thread_cls:
                mock_thread = MagicMock()
                mock_thread_cls.return_value = mock_thread
                exp.start()
                mock_thread.start.assert_called_once()

    def test_stop(self):
        exp = PrometheusExporter()
        mock_server = MagicMock()
        exp._server = mock_server
        exp.stop()
        mock_server.shutdown.assert_called_once()

    def test_stop_no_server(self):
        exp = PrometheusExporter()
        exp.stop()  # must not raise
