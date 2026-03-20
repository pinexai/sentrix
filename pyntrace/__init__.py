"""
pyntrace — Red-team, eval, and monitor your LLMs. Security-first, Python-native.

Quick start:
    import pyntrace
    pyntrace.init()

    # Red team your chatbot
    report = pyntrace.red_team(my_chatbot, plugins=["jailbreak", "pii"])
    report.summary()

    # Attack heatmap across models
    fp = pyntrace.guard.fingerprint({"gpt-4o-mini": fn1, "claude-haiku": fn2})
    fp.heatmap()

    # Auto-generate test cases
    ds = pyntrace.auto_dataset(my_chatbot, n=50, focus="adversarial")
"""
from __future__ import annotations

__version__ = "0.5.1"
__author__ = "pyntrace"

# Guard (primary — security)
from pyntrace.guard.red_team import red_team, RedTeamReport
from pyntrace.guard.fingerprint import fingerprint, ModelFingerprint
from pyntrace.guard.auto_dataset import auto_dataset
from pyntrace.guard.swarm import scan_swarm, SwarmScanReport
from pyntrace.guard.toolchain import scan_toolchain, ToolchainReport
from pyntrace.guard.prompt_leakage import prompt_leakage_score, LeakageReport
from pyntrace.guard.multilingual import scan_multilingual, MultilingualReport
from pyntrace.guard.mcp_scanner import scan_mcp, MCPScanReport
from pyntrace.guard.mcp_static import analyze_mcp_tools, ToolRiskReport
from pyntrace.guard.conversation import scan_conversation, ConversationScanReport
from pyntrace.guard.model_audit import audit_model, audit_models, ModelAuditReport
from pyntrace.guard.attacks import attack_plugin, register_plugin, load_all_plugins

# Eval
from pyntrace.eval.dataset import Dataset, DatasetItem
from pyntrace.eval.experiment import Experiment, ExperimentResults
from pyntrace.eval import scorers
from pyntrace.eval.compare import compare_models, prompt_ab_test

# Monitor
from pyntrace.monitor.tracer import trace, span
from pyntrace.monitor.drift import DriftDetector, DriftReport
from pyntrace.monitor.alerts import AlertManager, AlertRule
from pyntrace.monitor.prometheus import PrometheusExporter, expose_metrics
from pyntrace.monitor.latency import benchmark_latency, LatencyReport

# Sub-packages
from pyntrace import guard, eval, monitor

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
    "scan_swarm",
    "SwarmScanReport",
    "scan_toolchain",
    "ToolchainReport",
    "prompt_leakage_score",
    "LeakageReport",
    "scan_multilingual",
    "MultilingualReport",
    "scan_mcp",
    "MCPScanReport",
    "analyze_mcp_tools",
    "ToolRiskReport",
    "scan_conversation",
    "ConversationScanReport",
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
    "AlertManager",
    "AlertRule",
    "PrometheusExporter",
    "expose_metrics",
    "benchmark_latency",
    "LatencyReport",
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
    Initialize pyntrace — enable persistence and activate SDK interceptors.

    Args:
        persist: write results to SQLite (default True)
        db_path: custom path for pyntrace.db (default: ~/.pyntrace/data.db)
        offline: use local Ollama model for judging (no external API calls)
        local_judge_model: Ollama model to use when offline=True
        judge_model: default judge model when offline=False

    Example:
        pyntrace.init()                              # Standard
        pyntrace.init(offline=True)                  # Fully offline with Ollama
        pyntrace.init(db_path="/tmp/pyntrace.db")     # Custom DB path
    """
    from pyntrace import providers, db

    # Load local secrets file (no-op if ~/.pyntrace/secrets.json doesn't exist)
    try:
        from pyntrace.secrets.store import load_secrets
        load_secrets()
    except Exception:
        pass

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
        from pyntrace import interceptor
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
