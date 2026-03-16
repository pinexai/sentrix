"""Review queue and annotation system for false-positive tracking."""
from __future__ import annotations

import json
import time
import uuid
from dataclasses import dataclass, field
from typing import Literal

Label = Literal["true_positive", "false_positive", "needs_review"]


@dataclass
class Annotation:
    id: str
    report_id: str
    result_id: str
    label: Label
    reviewer: str | None
    comment: str | None
    created_at: float

    def to_json(self) -> dict:
        return {
            "id": self.id,
            "report_id": self.report_id,
            "result_id": self.result_id,
            "label": self.label,
            "reviewer": self.reviewer,
            "comment": self.comment,
            "created_at": self.created_at,
        }

    def _persist(self) -> None:
        try:
            from pyntrace.db import get_conn
            conn = get_conn()
            with conn:
                conn.execute(
                    """INSERT OR REPLACE INTO review_annotations
                       (id, report_id, result_id, label, reviewer, comment, created_at)
                       VALUES (?, ?, ?, ?, ?, ?, ?)""",
                    (self.id, self.report_id, self.result_id, self.label,
                     self.reviewer, self.comment, self.created_at),
                )
            conn.close()
        except Exception as e:
            print(f"[pyntrace] Warning: could not persist annotation: {e}")


class ReviewQueue:
    def __init__(self, db_path: str | None = None):
        self._db_path = db_path

    def pending(self) -> list[dict]:
        """Return all flagged attack results that haven't been annotated yet."""
        from pyntrace.db import _q

        # Get all vulnerable attack results
        vuln_rows = _q(
            """SELECT rtr.id as report_id, rtr.target_fn,
                      rr.value as result_json
               FROM red_team_reports rtr,
                    json_each(rtr.results_json) rr
               WHERE json_extract(rr.value, '$.vulnerable') = 1
               LIMIT 200""",
            db_path=self._db_path
        )

        # Get already-annotated result IDs
        annotated = {
            r["result_id"]
            for r in _q("SELECT result_id FROM review_annotations", db_path=self._db_path)
        }

        pending = []
        for row in vuln_rows:
            try:
                result = json.loads(row["result_json"]) if isinstance(row.get("result_json"), str) else {}
                result_id = f"{row['report_id']}_{result.get('plugin', '')}_{hash(result.get('attack_input', ''))}"
                if result_id not in annotated:
                    pending.append({
                        "result_id": result_id,
                        "report_id": row["report_id"],
                        "target_fn": row["target_fn"],
                        "plugin": result.get("plugin"),
                        "attack_input": result.get("attack_input"),
                        "output": result.get("output"),
                        "judge_reasoning": result.get("judge_reasoning"),
                    })
            except Exception:
                pass
        return pending

    def annotate(
        self,
        result_id: str,
        label: Label,
        reviewer: str | None = None,
        comment: str | None = None,
        report_id: str = "",
    ) -> Annotation:
        """Annotate a result as true_positive, false_positive, or needs_review."""
        ann = Annotation(
            id=str(uuid.uuid4()),
            report_id=report_id,
            result_id=result_id,
            label=label,
            reviewer=reviewer,
            comment=comment,
            created_at=time.time(),
        )
        ann._persist()
        return ann

    def export(self, path: str) -> None:
        """Export all annotations to JSON (for retraining datasets)."""
        from pyntrace.db import _q
        rows = _q("SELECT * FROM review_annotations ORDER BY created_at", db_path=self._db_path)
        with open(path, "w") as f:
            json.dump(rows, f, indent=2)
        print(f"[pyntrace] Exported {len(rows)} annotations to {path}")

    def accuracy_report(self) -> dict:
        """Compute false positive rate per plugin."""
        from pyntrace.db import _q
        rows = _q("SELECT * FROM review_annotations", db_path=self._db_path)

        if not rows:
            return {}

        # We track label distribution overall and try to infer per-plugin
        label_counts: dict[str, dict] = {}
        for row in rows:
            label = row["label"]
            result_id = row.get("result_id", "")
            # Extract plugin from result_id heuristic
            parts = result_id.split("_")
            plugin = parts[1] if len(parts) > 2 else "unknown"
            label_counts.setdefault(plugin, {"true_positive": 0, "false_positive": 0, "needs_review": 0})
            if label in label_counts[plugin]:
                label_counts[plugin][label] += 1

        report = {}
        for plugin, counts in label_counts.items():
            total = sum(counts.values())
            fp_rate = counts["false_positive"] / total if total > 0 else 0.0
            report[plugin] = {
                **counts,
                "total": total,
                "false_positive_rate": fp_rate,
            }
        return report

    def list_annotations(self, limit: int = 50) -> list[Annotation]:
        from pyntrace.db import _q
        rows = _q(
            "SELECT * FROM review_annotations ORDER BY created_at DESC LIMIT ?",
            (limit,), db_path=self._db_path
        )
        return [
            Annotation(
                id=r["id"],
                report_id=r["report_id"],
                result_id=r["result_id"],
                label=r["label"],
                reviewer=r["reviewer"],
                comment=r["comment"],
                created_at=r["created_at"],
            )
            for r in rows
        ]


# Module-level helpers
_default_queue: ReviewQueue | None = None


def get_review_queue() -> ReviewQueue:
    global _default_queue
    if _default_queue is None:
        _default_queue = ReviewQueue()
    return _default_queue


def annotate(
    result_id: str,
    label: Label,
    reviewer: str | None = None,
    comment: str | None = None,
) -> Annotation:
    """Quick annotation helper."""
    return get_review_queue().annotate(result_id, label, reviewer, comment)
