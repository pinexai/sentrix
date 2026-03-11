"""
sentrix — Red-team, eval, and monitor your LLMs. Security-first, Python-native.

Quick start:
    import sentrix
    sentrix.init()

    # Red team your chatbot
    report = sentrix.red_team(my_chatbot, plugins=["jailbreak", "pii"])
    report.summary()

    # Attack heatmap across models
    fp = sentrix.guard.fingerprint({"gpt-4o-mini": fn1, "claude-haiku": fn2})
    fp.heatmap()

    # Auto-generate test cases
    ds = sentrix.auto_dataset(my_chatbot, n=50, focus="adversarial")
"""
from __future__ import annotations

__version__ = "0.1.0"
__author__ = "sentrix"

# Guard (primary — security)
from sentrix.guard.red_team import red_team, RedTeamReport
from sentrix.guard.fingerprint import fingerprint, ModelFingerprint
from sentrix.guard.auto_dataset import auto_dataset

# Eval
from sentrix.eval.dataset import Dataset, DatasetItem
from sentrix.eval.experiment import Experiment, ExperimentResults
from sentrix.eval import scorers
from sentrix.eval.compare import compare_models, prompt_ab_test

# Monitor
from sentrix.monitor.tracer import trace, span
from sentrix.monitor.drift import DriftDetector, DriftReport

# Sub-packages
from sentrix import guard, eval, monitor

__all__ = [
    # Core
    "init",
    "dataset",
    "experiment",
    # Guard
    "red_team",
    "RedTeamReport",
    "fingerprint",
    "ModelFingerprint",
    "auto_dataset",
    "guard",
    # Eval
    "Dataset",
    "DatasetItem",
    "Experiment",
    "ExperimentResults",
    "scorers",
    "compare_models",
    "prompt_ab_test",
    "eval",
    # Monitor
    "trace",
    "span",
    "DriftDetector",
    "DriftReport",
    "monitor",
]


def init(
    persist: bool = True,
    db_path: str | None = None,
    offline: bool = False,
    local_judge_model: str = "llama3",
    judge_model: str = "gpt-4o-mini",
) -> None:
    """
    Initialize sentrix — enable persistence and activate SDK interceptors.

    Args:
        persist: write results to SQLite (default True)
        db_path: custom path for sentrix.db (default: ~/.sentrix/data.db)
        offline: use local Ollama model for judging (no external API calls)
        local_judge_model: Ollama model to use when offline=True
        judge_model: default judge model when offline=False

    Example:
        sentrix.init()                              # Standard
        sentrix.init(offline=True)                  # Fully offline with Ollama
        sentrix.init(db_path="/tmp/sentrix.db")     # Custom DB path
    """
    from sentrix import providers, db

    # Configure providers
    providers.configure(
        offline=offline,
        local_judge_model=local_judge_model,
        judge_model=judge_model,
    )

    # Configure DB path
    if db_path:
        db.set_db_path(db_path)

    # Initialize DB schema
    if persist:
        db.init_db(db_path)

    # Activate SDK interceptors
    try:
        from sentrix import interceptor
        interceptor.activate()
    except Exception:
        pass


def dataset(name: str, description: str = "") -> Dataset:
    """Create or load a named dataset."""
    return Dataset(name, description)


def experiment(
    name: str,
    dataset: Dataset | str,
    fn,
    scorers: list | None = None,
) -> Experiment:
    """Create an experiment."""
    return Experiment(name=name, dataset=dataset, fn=fn, scorers=scorers or [])
