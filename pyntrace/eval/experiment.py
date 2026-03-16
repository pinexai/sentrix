"""Experiment runner — run a function against a dataset with scorers."""
from __future__ import annotations

import json
import time
import uuid
from dataclasses import dataclass, field
from typing import Any, Callable

from pyntrace.eval.dataset import Dataset, DatasetItem


@dataclass
class ExperimentResult:
    item: DatasetItem
    output: Any
    scores: dict[str, float | dict]
    passed: bool
    error: str | None
    cost_usd: float
    duration_ms: float
    git_commit: str | None = None


class ExperimentResults:
    def __init__(
        self,
        experiment_name: str,
        results: list[ExperimentResult],
        total_cost_usd: float,
        git_commit: str | None,
    ):
        self.experiment_name = experiment_name
        self.results = results
        self.total_cost_usd = total_cost_usd
        self.git_commit = git_commit
        self.created_at = time.time()

    @property
    def pass_rate(self) -> float:
        if not self.results:
            return 0.0
        return sum(1 for r in self.results if r.passed) / len(self.results)

    @property
    def avg_scores(self) -> dict[str, float]:
        if not self.results:
            return {}
        all_keys: set[str] = set()
        for r in self.results:
            for k, v in r.scores.items():
                if isinstance(v, (int, float)):
                    all_keys.add(k)
                elif isinstance(v, dict) and "score" in v:
                    all_keys.add(k)
        avgs = {}
        for key in all_keys:
            vals = []
            for r in self.results:
                v = r.scores.get(key)
                if isinstance(v, (int, float)):
                    vals.append(float(v))
                elif isinstance(v, dict) and "score" in v:
                    vals.append(float(v["score"]))
            avgs[key] = sum(vals) / len(vals) if vals else 0.0
        return avgs

    def summary(self) -> None:
        print(f"\n{'='*60}")
        print(f"Experiment: {self.experiment_name}")
        print(f"{'='*60}")
        print(f"  Pass rate  : {self.pass_rate:.1%} ({sum(1 for r in self.results if r.passed)}/{len(self.results)})")
        print(f"  Total cost : ${self.total_cost_usd:.4f}")
        print(f"  Git commit : {self.git_commit or 'N/A'}")
        print()

        avgs = self.avg_scores
        if avgs:
            print("  Average Scores:")
            for scorer, score in avgs.items():
                bar = "█" * int(score * 20)
                print(f"    {scorer:<30} {score:.3f} {bar}")

        errors = [r for r in self.results if r.error]
        if errors:
            print(f"\n  Errors: {len(errors)}")
            for r in errors[:3]:
                print(f"    {r.error}")
        print()

    def compare(self, name: str) -> None:
        """Compare scores against a stored experiment by name."""
        try:
            from pyntrace.db import _q
            import json
            rows = _q(
                "SELECT er.scores FROM experiment_results er JOIN experiments e ON er.experiment_id = e.id WHERE e.name = ? ORDER BY e.created_at DESC LIMIT 100",
                (name,)
            )
            if not rows:
                print(f"[pyntrace] No stored results for experiment '{name}'")
                return
            baseline_scores: dict[str, list[float]] = {}
            for row in rows:
                scores = json.loads(row["scores"]) if row["scores"] else {}
                for k, v in scores.items():
                    val = float(v["score"]) if isinstance(v, dict) and "score" in v else float(v)
                    baseline_scores.setdefault(k, []).append(val)
            baseline_avgs = {k: sum(v) / len(v) for k, v in baseline_scores.items()}
            current_avgs = self.avg_scores

            print(f"\nComparison: {self.experiment_name} vs {name}")
            print(f"  {'Scorer':<30} {'Baseline':>10} {'Current':>10} {'Delta':>10}")
            print("  " + "-" * 62)
            for scorer in set(baseline_avgs) | set(current_avgs):
                base = baseline_avgs.get(scorer, 0.0)
                curr = current_avgs.get(scorer, 0.0)
                delta = curr - base
                delta_str = f"{delta:+.3f}"
                color = "\033[92m" if delta >= 0 else "\033[91m"
                reset = "\033[0m"
                print(f"  {scorer:<30} {base:>10.3f} {curr:>10.3f} {color}{delta_str:>10}{reset}")
        except Exception as e:
            print(f"[pyntrace] Compare failed: {e}")

    def to_json(self) -> dict:
        return {
            "experiment_name": self.experiment_name,
            "pass_rate": self.pass_rate,
            "total_cost_usd": self.total_cost_usd,
            "git_commit": self.git_commit,
            "avg_scores": self.avg_scores,
            "results": [
                {
                    "input": r.item.input,
                    "output": r.output,
                    "scores": r.scores,
                    "passed": r.passed,
                    "error": r.error,
                    "cost_usd": r.cost_usd,
                    "duration_ms": r.duration_ms,
                }
                for r in self.results
            ],
        }

    def to_dataframe(self):
        try:
            import pandas as pd
        except ImportError:
            raise ImportError("pip install pandas")
        rows = []
        for r in self.results:
            row = {
                "input": r.item.input,
                "output": r.output,
                "passed": r.passed,
                "error": r.error,
                "cost_usd": r.cost_usd,
                "duration_ms": r.duration_ms,
            }
            for k, v in r.scores.items():
                row[f"score_{k}"] = v["score"] if isinstance(v, dict) and "score" in v else v
            rows.append(row)
        return pd.DataFrame(rows)


class Experiment:
    def __init__(
        self,
        name: str,
        dataset: Dataset | str,
        fn: Callable,
        scorers: list[Callable] | None = None,
        db_path: str | None = None,
    ):
        self.id = str(uuid.uuid4())
        self.name = name
        self.dataset = dataset
        self.fn = fn
        self.scorers = scorers or []
        self._db_path = db_path

    def run(self, pass_threshold: float = 0.5) -> ExperimentResults:
        from pyntrace.git_tracker import get_current_commit
        from pyntrace.eval.dataset import Dataset

        git_commit = get_current_commit()
        fn_name = getattr(self.fn, "__name__", str(self.fn))

        # Resolve dataset
        if isinstance(self.dataset, str):
            ds = Dataset(self.dataset, db_path=self._db_path)
        else:
            ds = self.dataset

        print(f"\n[pyntrace] Running experiment {self.name!r} on {len(ds)} items...")

        # Persist experiment record
        try:
            from pyntrace.db import get_conn
            conn = get_conn(self._db_path)
            with conn:
                conn.execute(
                    "INSERT OR REPLACE INTO experiments (id, name, dataset_id, function_name, created_at, git_commit) VALUES (?, ?, ?, ?, ?, ?)",
                    (self.id, self.name, ds.id, fn_name, time.time(), git_commit),
                )
            conn.close()
        except Exception:
            pass

        results: list[ExperimentResult] = []
        total_cost = 0.0

        for item in ds:
            t0 = time.perf_counter()
            error = None
            output = None

            try:
                output = self.fn(item.input)
            except Exception as e:
                error = str(e)
                output = ""

            duration_ms = (time.perf_counter() - t0) * 1000

            scores: dict[str, float | dict] = {}
            for scorer_fn in self.scorers:
                scorer_name = getattr(scorer_fn, "__name__", str(scorer_fn))
                try:
                    # Some scorers accept input kwarg
                    import inspect
                    sig = inspect.signature(scorer_fn)
                    if "input" in sig.parameters:
                        score = scorer_fn(str(output), str(item.expected_output or ""), input=str(item.input))
                    else:
                        score = scorer_fn(str(output), str(item.expected_output or ""))
                    scores[scorer_name] = score
                except Exception as e:
                    scores[scorer_name] = 0.0

            # Compute pass: average of numeric scores > threshold
            numeric_scores = []
            for v in scores.values():
                if isinstance(v, (int, float)):
                    numeric_scores.append(float(v))
                elif isinstance(v, dict) and "score" in v:
                    numeric_scores.append(float(v["score"]))

            passed = (sum(numeric_scores) / len(numeric_scores) >= pass_threshold) if numeric_scores else (error is None)

            result = ExperimentResult(
                item=item,
                output=output,
                scores=scores,
                passed=passed,
                error=error,
                cost_usd=0.0,
                duration_ms=duration_ms,
                git_commit=git_commit,
            )
            results.append(result)
            total_cost += result.cost_usd

            # Persist result
            try:
                from pyntrace.db import get_conn
                conn = get_conn(self._db_path)
                with conn:
                    conn.execute(
                        """INSERT INTO experiment_results
                           (id, experiment_id, dataset_item_id, output, scores, passed, error, cost_usd, duration_ms)
                           VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                        (str(uuid.uuid4()), self.id, item.id,
                         json.dumps(output), json.dumps(scores),
                         1 if passed else 0, error, result.cost_usd, duration_ms),
                    )
                conn.close()
            except Exception:
                pass

        return ExperimentResults(
            experiment_name=self.name,
            results=results,
            total_cost_usd=total_cost,
            git_commit=git_commit,
        )
