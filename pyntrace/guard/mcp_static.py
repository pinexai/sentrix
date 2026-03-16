"""Static MCP tool schema analyzer — no running server needed.

Analyzes MCP tool definitions (name + description) to detect dangerous tool
combinations, privilege escalation paths, and data exfiltration chains.
Zero LLM calls — pure keyword + graph matching.
"""
from __future__ import annotations

from dataclasses import dataclass, field


# ---------------------------------------------------------------------------
# Risk category detection (keyword-based)
# ---------------------------------------------------------------------------

_CATEGORY_KEYWORDS: dict[str, list[str]] = {
    "filesystem": [
        "file", "read", "write", "disk", "path", "directory", "folder",
        "load", "save", "store", "open", "delete", "remove", "create",
    ],
    "network": [
        "http", "request", "fetch", "url", "webhook", "api", "send",
        "post", "get", "download", "upload", "transfer", "outbound",
    ],
    "email": [
        "email", "mail", "smtp", "send", "message", "notify", "alert",
    ],
    "code_execution": [
        "exec", "execute", "run", "eval", "shell", "cmd", "subprocess",
        "compile", "spawn", "invoke", "python", "bash", "script",
    ],
    "database": [
        "database", "db", "sql", "query", "table", "record", "row",
        "select", "insert", "update", "delete", "postgres", "mysql", "sqlite",
    ],
    "credentials": [
        "password", "secret", "token", "key", "credential", "auth",
        "apikey", "api_key", "private", "sensitive",
    ],
    "memory": [
        "memory", "context", "history", "state", "cache", "store",
        "remember", "recall", "persist",
    ],
}

# Risk edges: (from_category, to_category) → (risk_name, severity, description)
_RISK_EDGES: dict[tuple[str, str], tuple[str, str, str]] = {
    ("filesystem", "network"):    ("data_exfiltration",    "CRITICAL", "Read files then send externally — data exfiltration chain"),
    ("filesystem", "email"):      ("data_exfiltration",    "CRITICAL", "Read files then send by email — data exfiltration chain"),
    ("database",   "network"):    ("data_exfiltration",    "CRITICAL", "Query database then send results externally"),
    ("database",   "email"):      ("data_exfiltration",    "CRITICAL", "Query database then send by email"),
    ("credentials","network"):    ("credential_exfiltration", "CRITICAL", "Access credentials then send externally"),
    ("credentials","email"):      ("credential_exfiltration", "CRITICAL", "Access credentials then send by email"),
    ("filesystem", "code_execution"): ("rce_escalation",  "HIGH",     "Read filesystem then execute code — privilege escalation"),
    ("database",   "code_execution"): ("rce_escalation",  "HIGH",     "Query database then execute arbitrary code"),
    ("network",    "code_execution"): ("rce_ssrf_chain",   "HIGH",     "Fetch external content then execute — SSRF + RCE chain"),
    ("memory",     "network"):    ("memory_leak",          "HIGH",     "Expose conversation history or state to external parties"),
    ("filesystem", "filesystem"): ("unrestricted_access",  "MEDIUM",   "Unrestricted read+write filesystem access"),
    ("database",   "filesystem"): ("data_dump",            "MEDIUM",   "Query database records to local files"),
}

# Per-tool risks (just from having a tool, regardless of chains)
_STANDALONE_RISKS: dict[str, tuple[str, str, str]] = {
    "code_execution": ("arbitrary_code_execution", "CRITICAL", "Tool can execute arbitrary code — highest risk category"),
    "credentials":    ("credential_access",        "HIGH",     "Tool has access to secrets/credentials"),
}


def _categorize_tool(tool: dict) -> list[str]:
    """Return all matching risk categories for an MCP tool definition."""
    name = (tool.get("name") or "").lower()
    desc = (tool.get("description") or "").lower()
    text = f"{name} {desc}"
    return [cat for cat, keywords in _CATEGORY_KEYWORDS.items() if any(kw in text for kw in keywords)]


# ---------------------------------------------------------------------------
# Report
# ---------------------------------------------------------------------------

@dataclass
class ToolRisk:
    tool_name: str
    categories: list[str]
    risk_name: str
    severity: str
    description: str
    chain: list[str] = field(default_factory=list)  # empty = standalone risk


@dataclass
class ToolRiskReport:
    tools_analyzed: list[str]
    risks: list[ToolRisk] = field(default_factory=list)

    @property
    def critical_count(self) -> int:
        return sum(1 for r in self.risks if r.severity == "CRITICAL")

    @property
    def high_count(self) -> int:
        return sum(1 for r in self.risks if r.severity == "HIGH")

    @property
    def medium_count(self) -> int:
        return sum(1 for r in self.risks if r.severity == "MEDIUM")

    def summary(self) -> None:
        print(f"\n[pyntrace] MCP Static Analysis — {len(self.tools_analyzed)} tools")
        print(f"  Tools: {', '.join(self.tools_analyzed)}")
        print(f"  Risks: CRITICAL={self.critical_count}  HIGH={self.high_count}  MEDIUM={self.medium_count}")

        if not self.risks:
            print("  \033[92mNo dangerous tool combinations detected.\033[0m")
            return

        print()
        for risk in sorted(self.risks, key=lambda r: {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}.get(r.severity, 4)):
            sev_color = "\033[91m" if risk.severity in ("CRITICAL", "HIGH") else "\033[93m"
            chain_str = " → ".join(risk.chain) if risk.chain else risk.tool_name
            print(f"  [{sev_color}{risk.severity}\033[0m] {risk.risk_name}")
            print(f"    Chain : {chain_str}")
            print(f"    Reason: {risk.description}")
        print()

    def to_json(self) -> dict:
        return {
            "tools_analyzed": self.tools_analyzed,
            "critical_count": self.critical_count,
            "high_count": self.high_count,
            "medium_count": self.medium_count,
            "risks": [
                {
                    "tool_name": r.tool_name,
                    "categories": r.categories,
                    "risk_name": r.risk_name,
                    "severity": r.severity,
                    "description": r.description,
                    "chain": r.chain,
                }
                for r in self.risks
            ],
        }


# ---------------------------------------------------------------------------
# Analyzer
# ---------------------------------------------------------------------------

def analyze_mcp_tools(tools: list[dict]) -> ToolRiskReport:
    """
    Statically analyze MCP tool schemas for security risks.

    Args:
        tools: list of MCP tool dicts with 'name' and 'description' fields

    Returns:
        ToolRiskReport with all detected standalone and chain risks

    Example::

        report = analyze_mcp_tools([
            {"name": "read_file", "description": "Read any file from the filesystem"},
            {"name": "send_email", "description": "Send an email to any address"},
        ])
        report.summary()
        # CRITICAL: data_exfiltration — read_file → send_email
    """
    tool_names = [t.get("name", f"tool_{i}") for i, t in enumerate(tools)]
    tool_categories: dict[str, list[str]] = {
        t.get("name", f"tool_{i}"): _categorize_tool(t)
        for i, t in enumerate(tools)
    }

    risks: list[ToolRisk] = []
    seen_risks: set[tuple] = set()  # deduplicate

    # 1. Standalone per-tool risks
    for tool in tools:
        name = tool.get("name", "")
        cats = tool_categories[name]
        for cat in cats:
            if cat in _STANDALONE_RISKS:
                risk_name, severity, desc = _STANDALONE_RISKS[cat]
                key = (name, risk_name)
                if key not in seen_risks:
                    seen_risks.add(key)
                    risks.append(ToolRisk(
                        tool_name=name,
                        categories=cats,
                        risk_name=risk_name,
                        severity=severity,
                        description=desc,
                        chain=[name],
                    ))

    # 2. Chain risks — check all pairs and triples for risk edges
    for i, tool_a in enumerate(tools):
        name_a = tool_a.get("name", f"tool_{i}")
        cats_a = tool_categories[name_a]

        for j, tool_b in enumerate(tools):
            if i == j:
                continue
            name_b = tool_b.get("name", f"tool_{j}")
            cats_b = tool_categories[name_b]

            for cat_a in cats_a:
                for cat_b in cats_b:
                    edge_key = (cat_a, cat_b)
                    if edge_key in _RISK_EDGES:
                        risk_name, severity, desc = _RISK_EDGES[edge_key]
                        chain_key = (name_a, name_b, risk_name)
                        if chain_key not in seen_risks:
                            seen_risks.add(chain_key)
                            risks.append(ToolRisk(
                                tool_name=name_a,
                                categories=cats_a,
                                risk_name=risk_name,
                                severity=severity,
                                description=desc,
                                chain=[name_a, name_b],
                            ))

            # 3. Triple chains (A → B → C)
            for k, tool_c in enumerate(tools):
                if k == i or k == j:
                    continue
                name_c = tool_c.get("name", f"tool_{k}")
                cats_c = tool_categories[name_c]
                for cat_a in cats_a:
                    for cat_b in cats_b:
                        for cat_c in cats_c:
                            if (cat_a, cat_b) in _RISK_EDGES and (cat_b, cat_c) in _RISK_EDGES:
                                r1 = _RISK_EDGES[(cat_a, cat_b)]
                                r2 = _RISK_EDGES[(cat_b, cat_c)]
                                # Use the higher severity of the two edges
                                sev_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
                                severity = r1[1] if sev_order.get(r1[1], 9) <= sev_order.get(r2[1], 9) else r2[1]
                                chain_key = (name_a, name_b, name_c, "chain")
                                if chain_key not in seen_risks:
                                    seen_risks.add(chain_key)
                                    risks.append(ToolRisk(
                                        tool_name=name_a,
                                        categories=cats_a,
                                        risk_name="multi_step_chain",
                                        severity=severity,
                                        description=f"{r1[2]} — then: {r2[2]}",
                                        chain=[name_a, name_b, name_c],
                                    ))

    return ToolRiskReport(tools_analyzed=tool_names, risks=risks)
