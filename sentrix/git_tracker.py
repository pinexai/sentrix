"""Git SHA tagging and branch-based scan comparison."""
from __future__ import annotations

import subprocess
from dataclasses import dataclass


def get_current_commit() -> str | None:
    """Return current git HEAD SHA or None if not in a git repo."""
    try:
        result = subprocess.run(
            ["git", "rev-parse", "HEAD"],
            capture_output=True, text=True, timeout=5
        )
        if result.returncode == 0:
            return result.stdout.strip()
    except Exception:
        pass
    return None


def get_current_branch() -> str | None:
    try:
        result = subprocess.run(
            ["git", "rev-parse", "--abbrev-ref", "HEAD"],
            capture_output=True, text=True, timeout=5
        )
        if result.returncode == 0:
            return result.stdout.strip()
    except Exception:
        pass
    return None


def get_commit_for_ref(ref: str) -> str | None:
    """Resolve a branch/tag/ref to its full commit SHA."""
    try:
        result = subprocess.run(
            ["git", "rev-parse", ref],
            capture_output=True, text=True, timeout=5
        )
        if result.returncode == 0:
            return result.stdout.strip()
    except Exception:
        pass
    return None


@dataclass
class ScanComparison:
    base_ref: str
    head_ref: str
    base_vulnerability_rate: float
    head_vulnerability_rate: float
    delta: float
    has_regression: bool
    plugin_deltas: dict[str, float]

    def summary(self) -> None:
        status = "REGRESSION" if self.has_regression else "OK"
        print(f"\nScan Comparison: {self.base_ref} → {self.head_ref}")
        print(f"  Base vulnerability rate : {self.base_vulnerability_rate:.1%}")
        print(f"  Head vulnerability rate : {self.head_vulnerability_rate:.1%}")
        print(f"  Delta                   : {self.delta:+.1%}")
        print(f"  Status                  : {status}")
        if self.plugin_deltas:
            print("  Per-plugin deltas:")
            for plugin, delta in self.plugin_deltas.items():
                print(f"    {plugin:<20} {delta:+.1%}")

    def write_gha_annotation(self) -> None:
        import os
        summary_path = os.environ.get("GITHUB_STEP_SUMMARY")
        if not summary_path:
            return
        status = "REGRESSION ❌" if self.has_regression else "OK ✅"
        lines = [
            f"## sentrix Security Scan — {status}",
            f"| | Rate |",
            f"|---|---|",
            f"| Base (`{self.base_ref}`) | {self.base_vulnerability_rate:.1%} |",
            f"| Head (`{self.head_ref}`) | {self.head_vulnerability_rate:.1%} |",
            f"| Delta | {self.delta:+.1%} |",
        ]
        if self.plugin_deltas:
            lines.append("\n### Per-plugin breakdown")
            lines.append("| Plugin | Delta |")
            lines.append("|---|---|")
            for plugin, delta in self.plugin_deltas.items():
                lines.append(f"| {plugin} | {delta:+.1%} |")
        with open(summary_path, "a") as f:
            f.write("\n".join(lines) + "\n")


def compare_scans(
    base_ref: str,
    head_ref: str,
    db_path: str | None = None,
) -> ScanComparison:
    """Load red_team_reports for both refs and compute vulnerability delta."""
    from sentrix.db import _q

    base_commit = get_commit_for_ref(base_ref)
    head_commit = get_commit_for_ref(head_ref) or get_current_commit()

    def _load_rate(commit: str | None) -> tuple[float, dict[str, float]]:
        if not commit:
            return 0.0, {}
        rows = _q(
            "SELECT results_json, vulnerability_rate FROM red_team_reports WHERE git_commit LIKE ? ORDER BY created_at DESC LIMIT 1",
            (f"{commit[:8]}%",),
            db_path,
        )
        if not rows:
            return 0.0, {}
        import json
        results = json.loads(rows[0]["results_json"])
        plugin_rates: dict[str, list[float]] = {}
        for r in results:
            p = r.get("plugin", "unknown")
            plugin_rates.setdefault(p, []).append(1.0 if r.get("vulnerable") else 0.0)
        return rows[0]["vulnerability_rate"], {
            p: sum(v) / len(v) for p, v in plugin_rates.items()
        }

    base_rate, base_plugins = _load_rate(base_commit)
    head_rate, head_plugins = _load_rate(head_commit)

    plugin_deltas = {}
    for plugin in set(base_plugins) | set(head_plugins):
        plugin_deltas[plugin] = head_plugins.get(plugin, 0) - base_plugins.get(plugin, 0)

    delta = head_rate - base_rate
    return ScanComparison(
        base_ref=base_ref,
        head_ref=head_ref,
        base_vulnerability_rate=base_rate,
        head_vulnerability_rate=head_rate,
        delta=delta,
        has_regression=delta > 0.05,
        plugin_deltas=plugin_deltas,
    )


@dataclass
class ExperimentComparison:
    base_ref: str
    head_ref: str
    experiment_name: str
    base_score: float
    head_score: float
    delta: float
    has_regression: bool

    def summary(self) -> None:
        status = "REGRESSION" if self.has_regression else "OK"
        print(f"\nExperiment Comparison [{self.experiment_name}]: {self.base_ref} → {self.head_ref}")
        print(f"  Base score : {self.base_score:.3f}")
        print(f"  Head score : {self.head_score:.3f}")
        print(f"  Delta      : {self.delta:+.3f}")
        print(f"  Status     : {status}")


def compare_experiments(
    base_ref: str,
    head_ref: str,
    name: str,
    db_path: str | None = None,
) -> ExperimentComparison:
    from sentrix.db import _q
    import json

    base_commit = get_commit_for_ref(base_ref)
    head_commit = get_commit_for_ref(head_ref) or get_current_commit()

    def _load_score(commit: str | None) -> float:
        if not commit:
            return 0.0
        rows = _q(
            """SELECT er.scores FROM experiment_results er
               JOIN experiments e ON er.experiment_id = e.id
               WHERE e.name = ? AND e.git_commit LIKE ?
               ORDER BY e.created_at DESC""",
            (name, f"{commit[:8]}%"),
            db_path,
        )
        if not rows:
            return 0.0
        scores_list = []
        for row in rows:
            try:
                s = json.loads(row["scores"])
                vals = list(s.values()) if isinstance(s, dict) else []
                if vals:
                    scores_list.append(sum(float(v) for v in vals) / len(vals))
            except Exception:
                pass
        return sum(scores_list) / len(scores_list) if scores_list else 0.0

    base_score = _load_score(base_commit)
    head_score = _load_score(head_commit)
    delta = head_score - base_score

    return ExperimentComparison(
        base_ref=base_ref,
        head_ref=head_ref,
        experiment_name=name,
        base_score=base_score,
        head_score=head_score,
        delta=delta,
        has_regression=delta < -0.05,
    )
