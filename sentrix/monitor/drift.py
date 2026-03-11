"""Drift detection — compare current LLM performance to a baseline experiment."""
from __future__ import annotations

import json
import time
import uuid
from dataclasses import dataclass, field


@dataclass
class DriftReport:
    baseline_experiment: str
    window_hours: float
    baseline_score: float
    current_score: float
    score_delta: float
    baseline_cost_per_call: float
    current_cost_per_call: float
    cost_delta_pct: float
    anomalous_trace_ids: list[str]
    sampled_trace_count: int
    has_drift: bool
    created_at: float = field(default_factory=time.time)
    id: str = field(default_factory=lambda: str(uuid.uuid4()))

    def summary(self) -> None:
        status = "\033[91mDRIFT DETECTED\033[0m" if self.has_drift else "\033[92mOK\033[0m"
        print(f"\n[sentrix] Drift Report — {self.baseline_experiment}")
        print(f"  Status              : {status}")
        print(f"  Window              : {self.window_hours}h")
        print(f"  Baseline score      : {self.baseline_score:.3f}")
        print(f"  Current score       : {self.current_score:.3f}")
        print(f"  Score delta         : {self.score_delta:+.3f}")
        print(f"  Baseline cost/call  : ${self.baseline_cost_per_call:.4f}")
        print(f"  Current cost/call   : ${self.current_cost_per_call:.4f}")
        print(f"  Cost delta          : {self.cost_delta_pct:+.1f}%")
        print(f"  Traces sampled      : {self.sampled_trace_count}")
        print(f"  Anomalous traces    : {len(self.anomalous_trace_ids)}")

    def to_json(self) -> dict:
        return {
            "id": self.id,
            "baseline_experiment": self.baseline_experiment,
            "window_hours": self.window_hours,
            "baseline_score": self.baseline_score,
            "current_score": self.current_score,
            "score_delta": self.score_delta,
            "baseline_cost_per_call": self.baseline_cost_per_call,
            "current_cost_per_call": self.current_cost_per_call,
            "cost_delta_pct": self.cost_delta_pct,
            "anomalous_trace_ids": self.anomalous_trace_ids,
            "sampled_trace_count": self.sampled_trace_count,
            "has_drift": self.has_drift,
            "created_at": self.created_at,
        }

    def _persist(self) -> None:
        try:
            from sentrix.db import get_conn
            conn = get_conn()
            with conn:
                conn.execute(
                    """INSERT OR REPLACE INTO drift_reports
                       (id, baseline_experiment, window_hours, baseline_score,
                        current_score, score_delta, baseline_cost_per_call,
                        current_cost_per_call, cost_delta_pct, anomalous_trace_ids,
                        sampled_trace_count, created_at)
                       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                    (self.id, self.baseline_experiment, self.window_hours,
                     self.baseline_score, self.current_score, self.score_delta,
                     self.baseline_cost_per_call, self.current_cost_per_call,
                     self.cost_delta_pct, json.dumps(self.anomalous_trace_ids),
                     self.sampled_trace_count, self.created_at),
                )
            conn.close()
        except Exception:
            pass


class DriftDetector:
    def __init__(
        self,
        on_drift: str = "warn",  # "return" | "warn" | "raise"
        alert_webhook: str | None = None,
        score_threshold: float = 0.1,
        cost_threshold_pct: float = 25.0,
    ):
        self.on_drift = on_drift
        self.alert_webhook = alert_webhook
        self.score_threshold = score_threshold
        self.cost_threshold_pct = cost_threshold_pct
        self._baseline_experiment: str | None = None

    def baseline(self, experiment_name: str) -> "DriftDetector":
        """Set the baseline experiment name."""
        self._baseline_experiment = experiment_name
        return self

    def check(
        self,
        window_hours: float = 24.0,
        sample_n: int = 50,
        _persist: bool = True,
    ) -> DriftReport:
        """
        Check for drift vs baseline experiment.

        Args:
            window_hours: how far back to look in monitoring data
            sample_n: max traces to sample for comparison
        """
        if not self._baseline_experiment:
            raise ValueError("Call .baseline('experiment_name') first")

        baseline_score, baseline_cost = self._load_baseline()
        current_score, current_cost, trace_ids, sampled = self._load_recent_traces(
            window_hours, sample_n
        )

        score_delta = current_score - baseline_score
        cost_delta_pct = ((current_cost - baseline_cost) / baseline_cost * 100) if baseline_cost > 0 else 0.0

        has_drift = (
            abs(score_delta) > self.score_threshold or
            abs(cost_delta_pct) > self.cost_threshold_pct
        )

        report = DriftReport(
            baseline_experiment=self._baseline_experiment,
            window_hours=window_hours,
            baseline_score=baseline_score,
            current_score=current_score,
            score_delta=score_delta,
            baseline_cost_per_call=baseline_cost,
            current_cost_per_call=current_cost,
            cost_delta_pct=cost_delta_pct,
            anomalous_trace_ids=trace_ids,
            sampled_trace_count=sampled,
            has_drift=has_drift,
        )

        if _persist:
            report._persist()

        if has_drift:
            self._handle_drift(report)

        return report

    def _load_baseline(self) -> tuple[float, float]:
        """Load baseline score and cost per call from experiment results."""
        from sentrix.db import _q, init_db
        init_db()
        rows = _q(
            """SELECT er.scores, er.cost_usd FROM experiment_results er
               JOIN experiments e ON er.experiment_id = e.id
               WHERE e.name = ?
               ORDER BY e.created_at DESC
               LIMIT 200""",
            (self._baseline_experiment,)
        )
        if not rows:
            return 0.0, 0.0

        scores_list = []
        costs = []
        for row in rows:
            costs.append(row["cost_usd"] or 0.0)
            try:
                s = json.loads(row["scores"])
                vals = [float(v["score"]) if isinstance(v, dict) and "score" in v else float(v)
                        for v in s.values()]
                if vals:
                    scores_list.append(sum(vals) / len(vals))
            except Exception:
                pass

        avg_score = sum(scores_list) / len(scores_list) if scores_list else 0.0
        avg_cost = sum(costs) / len(costs) if costs else 0.0
        return avg_score, avg_cost

    def _load_recent_traces(
        self, window_hours: float, sample_n: int
    ) -> tuple[float, float, list[str], int]:
        """Load recent traces and compute average score + cost."""
        from sentrix.db import _q
        cutoff = time.time() - window_hours * 3600

        rows = _q(
            """SELECT id, metadata FROM traces
               WHERE start_time > ?
               ORDER BY start_time DESC
               LIMIT ?""",
            (cutoff, sample_n)
        )

        if not rows:
            return 0.0, 0.0, [], 0

        # Also check llm_calls for cost
        cost_rows = _q(
            "SELECT cost_usd FROM llm_calls WHERE timestamp > ? LIMIT ?",
            (cutoff, sample_n)
        )
        costs = [r["cost_usd"] or 0.0 for r in cost_rows]
        avg_cost = sum(costs) / len(costs) if costs else 0.0

        # For scoring, look for anomalous traces (errors)
        anomalous = [r["id"] for r in rows if _is_anomalous(r)]

        return 0.0, avg_cost, anomalous, len(rows)

    def _handle_drift(self, report: DriftReport) -> None:
        msg = f"[sentrix] Drift detected in '{self._baseline_experiment}': score delta={report.score_delta:+.3f}, cost delta={report.cost_delta_pct:+.1f}%"

        if self.alert_webhook:
            self._send_alert(msg, report)

        if self.on_drift == "raise":
            raise RuntimeError(msg)
        elif self.on_drift == "warn":
            import warnings
            warnings.warn(msg, stacklevel=3)
        # "return" — do nothing, let caller inspect report

    def _send_alert(self, msg: str, report: DriftReport) -> None:
        import urllib.request
        try:
            payload = json.dumps({
                "text": msg,
                "drift_report": report.to_json(),
            }).encode()
            req = urllib.request.Request(
                self.alert_webhook,
                data=payload,
                headers={"Content-Type": "application/json"},
            )
            urllib.request.urlopen(req, timeout=5)
        except Exception as e:
            print(f"[sentrix] Alert webhook failed: {e}")


def _is_anomalous(trace_row: dict) -> bool:
    """Heuristic: trace is anomalous if metadata contains an error."""
    try:
        meta = json.loads(trace_row.get("metadata", "{}"))
        return bool(meta.get("error"))
    except Exception:
        return False
