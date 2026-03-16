"""pyntrace latency profiler — p50/p95/p99 benchmarking for LLM functions."""
from __future__ import annotations

import json
import time
import uuid
from dataclasses import dataclass, field
from typing import Callable


def _percentile(sorted_values: list[float], p: float) -> float:
    """Return the p-th percentile (0-100) of a pre-sorted list. Pure stdlib."""
    if not sorted_values:
        return 0.0
    n = len(sorted_values)
    idx = (p / 100) * (n - 1)
    lo = int(idx)
    hi = min(lo + 1, n - 1)
    frac = idx - lo
    return sorted_values[lo] * (1 - frac) + sorted_values[hi] * frac


@dataclass
class PromptLatency:
    """Latency stats for a single prompt across n_runs."""
    prompt: str
    latencies_ms: list[float]
    p50_ms: float
    p95_ms: float
    p99_ms: float
    min_ms: float
    max_ms: float
    mean_ms: float

    def to_dict(self) -> dict:
        return {
            "prompt": self.prompt[:80] + "..." if len(self.prompt) > 80 else self.prompt,
            "p50_ms": round(self.p50_ms, 2),
            "p95_ms": round(self.p95_ms, 2),
            "p99_ms": round(self.p99_ms, 2),
            "min_ms": round(self.min_ms, 2),
            "max_ms": round(self.max_ms, 2),
            "mean_ms": round(self.mean_ms, 2),
        }


@dataclass
class LatencyReport:
    """Full latency benchmark report."""
    id: str
    fn_name: str
    n_prompts: int
    n_runs: int
    # Aggregate across all prompts
    p50_ms: float
    p95_ms: float
    p99_ms: float
    mean_ms: float
    min_ms: float
    max_ms: float
    per_prompt: list[PromptLatency] = field(default_factory=list)
    created_at: float = field(default_factory=time.time)

    def summary(self) -> None:
        """Print a colored summary to stdout."""
        print(f"\n[pyntrace] Latency Benchmark — {self.fn_name}")
        print(f"  Prompts: {self.n_prompts}  Runs/prompt: {self.n_runs}")
        print(f"  p50:  {self.p50_ms:.0f} ms")
        print(f"  p95:  {self.p95_ms:.0f} ms")
        print(f"  p99:  {self.p99_ms:.0f} ms")
        print(f"  min:  {self.min_ms:.0f} ms   max: {self.max_ms:.0f} ms   mean: {self.mean_ms:.0f} ms")

        if self.p95_ms < 1000:
            status = "\033[32m✓ Excellent (<1s p95)\033[0m"
        elif self.p95_ms < 2000:
            status = "\033[33m~ Good (<2s p95)\033[0m"
        elif self.p95_ms < 5000:
            status = "\033[33m⚠ Acceptable (<5s p95)\033[0m"
        else:
            status = "\033[31m✗ Slow (>5s p95)\033[0m"
        print(f"  Status: {status}")

    def to_json(self) -> dict:
        return {
            "id": self.id,
            "fn_name": self.fn_name,
            "n_prompts": self.n_prompts,
            "n_runs": self.n_runs,
            "p50_ms": round(self.p50_ms, 2),
            "p95_ms": round(self.p95_ms, 2),
            "p99_ms": round(self.p99_ms, 2),
            "mean_ms": round(self.mean_ms, 2),
            "min_ms": round(self.min_ms, 2),
            "max_ms": round(self.max_ms, 2),
            "per_prompt": [p.to_dict() for p in self.per_prompt],
            "created_at": self.created_at,
        }

    def _persist(self, db_path: str | None = None) -> None:
        try:
            from pyntrace.db import get_conn
            conn = get_conn(db_path)
            with conn:
                conn.execute(
                    """INSERT OR REPLACE INTO latency_reports
                       (id, fn_name, n_prompts, n_runs, p50_ms, p95_ms, p99_ms,
                        mean_ms, min_ms, max_ms, results_json, created_at)
                       VALUES (?,?,?,?,?,?,?,?,?,?,?,?)""",
                    (
                        self.id, self.fn_name, self.n_prompts, self.n_runs,
                        self.p50_ms, self.p95_ms, self.p99_ms,
                        self.mean_ms, self.min_ms, self.max_ms,
                        json.dumps([p.to_dict() for p in self.per_prompt]),
                        self.created_at,
                    ),
                )
        except Exception:
            pass


def benchmark_latency(
    fn: Callable[[str], str],
    prompts: list[str],
    n_runs: int = 3,
    warmup: int = 1,
    _persist: bool = True,
) -> LatencyReport:
    """
    Benchmark the latency of an LLM function across a list of prompts.

    Args:
        fn:       Callable that takes a string prompt and returns a string.
        prompts:  List of test prompts to benchmark.
        n_runs:   Number of timed runs per prompt (after warmup).
        warmup:   Number of discarded warm-up calls per prompt.
        _persist: Save results to SQLite.

    Returns:
        LatencyReport with p50/p95/p99 and per-prompt breakdown.

    Example::

        from pyntrace.monitor.latency import benchmark_latency

        report = benchmark_latency(my_chatbot, prompts=[
            "What is 2+2?",
            "Tell me about Python",
        ], n_runs=5)
        report.summary()
    """
    fn_name = getattr(fn, "__name__", repr(fn))
    per_prompt: list[PromptLatency] = []
    all_latencies: list[float] = []

    total = len(prompts)
    for i, prompt in enumerate(prompts, 1):
        print(f"\r[pyntrace] Benchmarking {i}/{total} prompts...", end="", flush=True)

        # Warm-up runs (discarded)
        for _ in range(warmup):
            try:
                fn(prompt)
            except Exception:
                pass

        # Timed runs
        latencies: list[float] = []
        for _ in range(n_runs):
            t0 = time.perf_counter()
            try:
                fn(prompt)
            except Exception:
                pass
            latencies.append((time.perf_counter() - t0) * 1000)

        latencies.sort()
        all_latencies.extend(latencies)
        per_prompt.append(PromptLatency(
            prompt=prompt,
            latencies_ms=latencies,
            p50_ms=_percentile(latencies, 50),
            p95_ms=_percentile(latencies, 95),
            p99_ms=_percentile(latencies, 99),
            min_ms=latencies[0],
            max_ms=latencies[-1],
            mean_ms=sum(latencies) / len(latencies),
        ))

    print()  # newline after progress

    all_latencies.sort()
    report = LatencyReport(
        id=str(uuid.uuid4()),
        fn_name=fn_name,
        n_prompts=len(prompts),
        n_runs=n_runs,
        p50_ms=_percentile(all_latencies, 50),
        p95_ms=_percentile(all_latencies, 95),
        p99_ms=_percentile(all_latencies, 99),
        mean_ms=sum(all_latencies) / len(all_latencies) if all_latencies else 0.0,
        min_ms=all_latencies[0] if all_latencies else 0.0,
        max_ms=all_latencies[-1] if all_latencies else 0.0,
        per_prompt=per_prompt,
    )

    if _persist:
        report._persist()

    return report
