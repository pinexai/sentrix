"""Tests for benchmark_latency()."""
import pytest
from pyntrace.monitor.latency import benchmark_latency, LatencyReport, PromptLatency, _percentile


def fast_fn(prompt: str) -> str:
    return f"response to: {prompt}"


def slow_fn(prompt: str) -> str:
    import time
    time.sleep(0.01)
    return "done"


def error_fn(prompt: str) -> str:
    raise ValueError("always fails")


class TestPercentile:
    def test_single_value(self):
        assert _percentile([5.0], 50) == 5.0
        assert _percentile([5.0], 99) == 5.0

    def test_empty(self):
        assert _percentile([], 50) == 0.0

    def test_two_values(self):
        vals = [10.0, 20.0]
        assert _percentile(vals, 0) == 10.0
        assert _percentile(vals, 100) == 20.0
        assert _percentile(vals, 50) == 15.0

    def test_monotonic(self):
        vals = sorted([1.0, 2.0, 3.0, 4.0, 5.0])
        p50 = _percentile(vals, 50)
        p95 = _percentile(vals, 95)
        p99 = _percentile(vals, 99)
        assert p50 <= p95 <= p99


class TestBenchmarkLatency:
    def test_returns_report(self):
        report = benchmark_latency(fast_fn, ["hello", "world"], n_runs=2, warmup=0, _persist=False)
        assert isinstance(report, LatencyReport)

    def test_fn_name(self):
        report = benchmark_latency(fast_fn, ["hello"], n_runs=1, warmup=0, _persist=False)
        assert report.fn_name == "fast_fn"

    def test_n_prompts(self):
        prompts = ["a", "b", "c"]
        report = benchmark_latency(fast_fn, prompts, n_runs=2, warmup=0, _persist=False)
        assert report.n_prompts == 3
        assert len(report.per_prompt) == 3

    def test_n_runs(self):
        report = benchmark_latency(fast_fn, ["hello"], n_runs=5, warmup=0, _persist=False)
        assert report.n_runs == 5
        assert len(report.per_prompt[0].latencies_ms) == 5

    def test_latencies_positive(self):
        report = benchmark_latency(fast_fn, ["hello", "world"], n_runs=3, warmup=0, _persist=False)
        assert report.min_ms >= 0
        assert report.max_ms >= report.min_ms
        assert report.p50_ms >= 0
        assert report.p95_ms >= report.p50_ms
        assert report.p99_ms >= report.p95_ms

    def test_error_fn_still_completes(self):
        # Errors inside fn are swallowed — latency is still recorded
        report = benchmark_latency(error_fn, ["hello"], n_runs=2, warmup=0, _persist=False)
        assert report.n_prompts == 1
        assert len(report.per_prompt[0].latencies_ms) == 2

    def test_per_prompt_stats(self):
        report = benchmark_latency(fast_fn, ["test"], n_runs=3, warmup=0, _persist=False)
        pp = report.per_prompt[0]
        assert isinstance(pp, PromptLatency)
        assert pp.prompt == "test"
        assert pp.p50_ms <= pp.p99_ms

    def test_to_json(self):
        report = benchmark_latency(fast_fn, ["hello"], n_runs=2, warmup=0, _persist=False)
        d = report.to_json()
        assert "id" in d
        assert "fn_name" in d
        assert "p50_ms" in d
        assert "p95_ms" in d
        assert "p99_ms" in d
        assert "per_prompt" in d
        assert isinstance(d["per_prompt"], list)

    def test_warmup_excluded(self):
        # warmup=2 means 2 discarded calls — final n_runs still 3
        report = benchmark_latency(fast_fn, ["hello"], n_runs=3, warmup=2, _persist=False)
        assert len(report.per_prompt[0].latencies_ms) == 3

    def test_slow_fn_latency_recorded(self):
        report = benchmark_latency(slow_fn, ["x"], n_runs=2, warmup=0, _persist=False)
        # 10ms sleep so min should be at least a few ms
        assert report.min_ms >= 1.0

    def test_summary_no_exception(self, capsys):
        report = benchmark_latency(fast_fn, ["hi"], n_runs=2, warmup=0, _persist=False)
        report.summary()
        out = capsys.readouterr().out
        assert "p95" in out
        assert "p50" in out
