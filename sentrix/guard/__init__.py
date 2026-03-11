"""sentrix.guard — Red teaming, attack heatmap, auto-dataset, agent security, RAG security."""
from sentrix.guard.red_team import red_team, RedTeamReport
from sentrix.guard.fingerprint import fingerprint, ModelFingerprint
from sentrix.guard.auto_dataset import auto_dataset
from sentrix.guard.attacks import PLUGIN_REGISTRY

__all__ = [
    "red_team",
    "RedTeamReport",
    "fingerprint",
    "ModelFingerprint",
    "auto_dataset",
    "PLUGIN_REGISTRY",
]
