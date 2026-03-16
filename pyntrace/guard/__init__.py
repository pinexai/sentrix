"""pyntrace.guard — Red teaming, attack heatmap, auto-dataset, agent security, RAG security."""
from pyntrace.guard.red_team import red_team, RedTeamReport
from pyntrace.guard.fingerprint import fingerprint, ModelFingerprint
from pyntrace.guard.auto_dataset import auto_dataset
from pyntrace.guard.attacks import PLUGIN_REGISTRY
from pyntrace.guard.swarm import scan_swarm, SwarmScanReport
from pyntrace.guard.toolchain import scan_toolchain, ToolchainReport
from pyntrace.guard.prompt_leakage import prompt_leakage_score, LeakageReport
from pyntrace.guard.multilingual import scan_multilingual, MultilingualReport
from pyntrace.guard.mcp_scanner import scan_mcp, MCPScanReport
from pyntrace.guard.mcp_static import analyze_mcp_tools, ToolRiskReport
from pyntrace.guard.mutations import get_mutated_attacks, mutate_attack
from pyntrace.guard.conversation import scan_conversation, ConversationScanReport

__all__ = [
    "red_team",
    "RedTeamReport",
    "fingerprint",
    "ModelFingerprint",
    "auto_dataset",
    "PLUGIN_REGISTRY",
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
    "get_mutated_attacks",
    "mutate_attack",
    "scan_conversation",
    "ConversationScanReport",
]
