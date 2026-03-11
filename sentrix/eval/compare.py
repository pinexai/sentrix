"""Model comparison — Pareto frontier and prompt A/B testing."""
from __future__ import annotations

import json
import time
import uuid
from dataclasses import dataclass, field
from typing import Callable

from sentrix.eval.dataset import Dataset


@dataclass
class ModelComparisonResult:
    prompt: str | None
    models: list[str]
    results: dict[str, dict]     # model → {avg_score, avg_cost, pass_rate}
    pareto_frontier: list[str]   # models not dominated on quality AND cost
    best_value: str | None       # highest quality/cost ratio on frontier
    created_at: float = field(default_factory=time.time)
    id: str = field(default_factory=lambda: str(uuid.uuid4()))

    def summary(self) -> None:
        print(f"\n[sentrix] Model Comparison")
        print(f"  {'Model':<25} {'Score':>8} {'Cost':>10} {'Pass%':>8} {'Label'}")
        print("  " + "-" * 65)
        for model in self.models:
            r = self.results.get(model, {})
            score = r.get("avg_score", 0.0)
            cost = r.get("avg_cost", 0.0)
            pass_rate = r.get("pass_rate", 0.0)
            labels = []
            if model == self.best_value:
                labels.append("* best-value")
            if model in self.pareto_frontier:
                labels.append("P pareto")
            label_str = ", ".join(labels)
            print(f"  {model:<25} {score:>8.3f} ${cost:>9.4f} {pass_rate:>7.1%} {label_str}")
        print()
        if self.best_value:
            print(f"  Recommendation: {self.best_value} (best quality/cost ratio)")

    def to_json(self) -> dict:
        return {
            "id": self.id,
            "prompt": self.prompt,
            "models": self.models,
            "results": self.results,
            "pareto_frontier": self.pareto_frontier,
            "best_value": self.best_value,
            "created_at": self.created_at,
        }

    def _persist(self) -> None:
        try:
            from sentrix.db import get_conn
            conn = get_conn()
            d = self.to_json()
            with conn:
                conn.execute(
                    """INSERT OR REPLACE INTO model_comparisons
                       (id, prompt, dataset_name, scorer_names, results_json, best_model, created_at)
                       VALUES (?, ?, ?, ?, ?, ?, ?)""",
                    (self.id, d["prompt"], "", json.dumps(d["models"]),
                     json.dumps(d["results"]), d["best_value"], self.created_at),
                )
            conn.close()
        except Exception:
            pass


def compare_models(
    prompt: str | None = None,
    models: dict[str, Callable] | None = None,
    dataset: Dataset | None = None,
    scorers: list[Callable] | None = None,
    pass_threshold: float = 0.5,
    _persist: bool = True,
) -> ModelComparisonResult:
    """
    Compare multiple models on a dataset or prompt.
    Returns Pareto frontier: models not dominated on both quality AND cost.

    Args:
        prompt: single prompt to test (if no dataset)
        models: {"model-name": callable} — each takes a prompt, returns str
        dataset: Dataset to run (if prompt not specified)
        scorers: list of scorer functions
        pass_threshold: minimum average score to consider a result passing
    """
    from sentrix.eval.experiment import Experiment
    from sentrix.eval.dataset import Dataset as DS
    from sentrix.pricing import calculate

    if models is None:
        raise ValueError("models dict is required")

    model_names = list(models.keys())
    all_results: dict[str, dict] = {}

    # Build dataset from prompt if no dataset provided
    if dataset is None and prompt:
        ds = DS(f"compare_{uuid.uuid4().hex[:6]}")
        ds.add(input=prompt)
    elif dataset is not None:
        ds = dataset
    else:
        raise ValueError("Either prompt or dataset must be provided")

    for model_name, fn in models.items():
        exp = Experiment(
            name=f"compare_{model_name}",
            dataset=ds,
            fn=fn,
            scorers=scorers or [],
        )
        exp_results = exp.run(pass_threshold=pass_threshold)
        all_results[model_name] = {
            "avg_score": sum(exp_results.avg_scores.values()) / len(exp_results.avg_scores) if exp_results.avg_scores else 0.0,
            "avg_cost": exp_results.total_cost_usd / max(len(ds), 1),
            "pass_rate": exp_results.pass_rate,
        }

    # Compute Pareto frontier (maximize score, minimize cost)
    pareto = []
    for m in model_names:
        dominated = False
        for other in model_names:
            if other == m:
                continue
            other_r = all_results[other]
            m_r = all_results[m]
            # other dominates m if it's at least as good on both dimensions
            if (other_r["avg_score"] >= m_r["avg_score"] and
                    other_r["avg_cost"] <= m_r["avg_cost"] and
                    (other_r["avg_score"] > m_r["avg_score"] or other_r["avg_cost"] < m_r["avg_cost"])):
                dominated = True
                break
        if not dominated:
            pareto.append(m)

    # Best value: highest score/cost ratio on Pareto frontier
    best_value = None
    best_ratio = -1.0
    for m in pareto:
        r = all_results[m]
        cost = r["avg_cost"] if r["avg_cost"] > 0 else 0.0001
        ratio = r["avg_score"] / cost
        if ratio > best_ratio:
            best_ratio = ratio
            best_value = m

    result = ModelComparisonResult(
        prompt=prompt,
        models=model_names,
        results=all_results,
        pareto_frontier=pareto,
        best_value=best_value,
    )

    if _persist:
        result._persist()

    return result


@dataclass
class PromptABResult:
    name: str
    v1_label: str
    v2_label: str
    v1_score: float
    v2_score: float
    winner: str
    significant: bool
    created_at: float = field(default_factory=time.time)

    def summary(self) -> None:
        print(f"\n[sentrix] Prompt A/B Test — {self.name}")
        print(f"  {self.v1_label:<30} score: {self.v1_score:.3f}")
        print(f"  {self.v2_label:<30} score: {self.v2_score:.3f}")
        print(f"  Winner: {self.winner}")
        if not self.significant:
            print("  (difference not statistically significant)")


def prompt_ab_test(
    name: str,
    v1: Callable,
    v2: Callable,
    dataset: Dataset,
    scorers: list[Callable] | None = None,
    model: str = "gpt-4o-mini",
    pass_threshold: float = 0.5,
) -> PromptABResult:
    """
    A/B test two prompt variants against a dataset.

    Args:
        name: experiment name
        v1: variant A callable
        v2: variant B callable
        dataset: evaluation dataset
        scorers: scoring functions
        model: model name tag
        pass_threshold: pass threshold for experiment
    """
    from sentrix.eval.experiment import Experiment

    exp_v1 = Experiment(f"{name}_v1", dataset, v1, scorers or [])
    exp_v2 = Experiment(f"{name}_v2", dataset, v2, scorers or [])

    r1 = exp_v1.run(pass_threshold)
    r2 = exp_v2.run(pass_threshold)

    score1 = sum(r1.avg_scores.values()) / max(len(r1.avg_scores), 1) if r1.avg_scores else r1.pass_rate
    score2 = sum(r2.avg_scores.values()) / max(len(r2.avg_scores), 1) if r2.avg_scores else r2.pass_rate

    winner = f"{name}_v1" if score1 >= score2 else f"{name}_v2"
    significant = abs(score1 - score2) > 0.05

    return PromptABResult(
        name=name,
        v1_label=f"{name}_v1",
        v2_label=f"{name}_v2",
        v1_score=score1,
        v2_score=score2,
        winner=winner,
        significant=significant,
    )
