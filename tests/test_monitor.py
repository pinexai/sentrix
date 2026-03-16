"""Tests for pyntrace.monitor — tracer, drift, daemon."""
import pytest
import time


class TestTracer:
    def test_trace_context_manager(self):
        from pyntrace.monitor.tracer import trace
        with trace("test-trace", input="hello") as t:
            t.output = "world"
        assert t.name == "test-trace"
        assert t.input == "hello"
        assert t.output == "world"
        assert t.end_time is not None
        assert t.end_time >= t.start_time

    def test_span_context_manager(self):
        from pyntrace.monitor.tracer import trace, span
        with trace("outer-trace") as t:
            with span("my-span", span_type="llm") as s:
                s.output = "response"
        assert s.name == "my-span"
        assert s.span_type == "llm"
        assert s.duration_ms >= 0

    def test_trace_captures_error(self):
        from pyntrace.monitor.tracer import trace
        with pytest.raises(ValueError):
            with trace("error-trace") as t:
                raise ValueError("test error")
        assert t.error == "test error"

    def test_trace_ids_propagated(self):
        from pyntrace.monitor.tracer import trace, span, _current_trace_id
        with trace("propagation-test") as t:
            assert _current_trace_id.get() == t.id
            with span("inner-span") as s:
                assert s.trace_id == t.id


class TestDriftDetector:
    def test_drift_detector_needs_baseline(self):
        from pyntrace.monitor.drift import DriftDetector
        det = DriftDetector()
        with pytest.raises(ValueError, match="baseline"):
            det.check()

    def test_drift_report_no_data(self, tmp_db):
        from pyntrace.monitor.drift import DriftDetector
        det = DriftDetector(on_drift="return")
        det.baseline("nonexistent-experiment")
        report = det.check(_persist=False)
        assert report.baseline_score == 0.0
        assert report.current_score == 0.0
        assert not report.has_drift

    def test_drift_report_to_json(self, tmp_db):
        from pyntrace.monitor.drift import DriftDetector
        det = DriftDetector(on_drift="return")
        det.baseline("test-exp")
        report = det.check(_persist=False)
        d = report.to_json()
        assert "baseline_experiment" in d
        assert "score_delta" in d
        assert "has_drift" in d


class TestPricingAndProviders:
    def test_calculate_known_model(self):
        from pyntrace.pricing import calculate
        cost = calculate("gpt-4o-mini", 1000, 500)
        assert cost > 0.0
        assert cost < 0.01  # Should be very cheap

    def test_calculate_unknown_model(self):
        from pyntrace.pricing import calculate
        cost = calculate("nonexistent-model-xyz", 1000, 500)
        assert cost == 0.0

    def test_get_cheaper_alternative(self):
        from pyntrace.pricing import get_cheaper_alternative
        alt = get_cheaper_alternative("gpt-4o")
        assert alt is not None
        assert alt == "gpt-4o-mini"

    def test_list_models(self):
        from pyntrace.pricing import list_models
        models = list_models()
        assert len(models) > 10
        assert all("model" in m and "input_per_1m" in m for m in models)
