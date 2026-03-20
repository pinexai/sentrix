"""Threat intelligence catalog for the pyntrace dashboard feed.

Combines:
  1. Built-in OWASP LLM Top 10 (2025) catalog
  2. Mapped pyntrace plugin for one-click scanning

The catalog is served statically (no network calls required).
"""
from __future__ import annotations

import time

# ── OWASP LLM Top 10 (2025) catalog ──────────────────────────────────────────
_OWASP_CATALOG: list[dict] = [
    {
        "id": "LLM01",
        "name": "Prompt Injection",
        "severity": "CRITICAL",
        "category": "injection",
        "description": (
            "Attackers craft inputs that override an LLM's system instructions, "
            "causing the model to execute unintended actions or disclose sensitive data. "
            "Includes direct injection via user messages and indirect injection via "
            "external content retrieved during RAG or tool calls."
        ),
        "pyntrace_plugin": "injection",
        "references": ["https://owasp.org/www-project-top-10-for-large-language-model-applications/"],
        "mitigations": [
            "Input sanitization and validation",
            "Privilege separation between system and user contexts",
            "Output monitoring and filtering",
        ],
        "published_at": 1700000000,
    },
    {
        "id": "LLM02",
        "name": "Sensitive Information Disclosure",
        "severity": "HIGH",
        "category": "pii",
        "description": (
            "LLMs may expose confidential training data, system prompts, API keys, "
            "or personal information either through direct extraction attacks or "
            "unintentional memorization of training data."
        ),
        "pyntrace_plugin": "pii",
        "references": ["https://owasp.org/www-project-top-10-for-large-language-model-applications/"],
        "mitigations": [
            "System prompt hardening",
            "PII masking in training data",
            "Output filtering for sensitive patterns",
        ],
        "published_at": 1700000001,
    },
    {
        "id": "LLM03",
        "name": "Supply Chain Vulnerabilities",
        "severity": "HIGH",
        "category": "supply_chain",
        "description": (
            "Compromised model weights, poisoned training data, malicious model files, "
            "or vulnerable third-party integrations can introduce backdoors or "
            "unexpected behaviors into LLM systems."
        ),
        "pyntrace_plugin": None,
        "references": ["https://owasp.org/www-project-top-10-for-large-language-model-applications/"],
        "mitigations": [
            "Use pyntrace audit-model to scan downloaded model files",
            "Verify model checksums against official sources",
            "Use safetensors instead of pickle-based formats",
        ],
        "published_at": 1700000002,
    },
    {
        "id": "LLM04",
        "name": "Data and Model Poisoning",
        "severity": "HIGH",
        "category": "poisoning",
        "description": (
            "Manipulation of training data or fine-tuning datasets to introduce "
            "backdoors, biases, or vulnerabilities that activate under specific "
            "trigger conditions at inference time."
        ),
        "pyntrace_plugin": None,
        "references": ["https://owasp.org/www-project-top-10-for-large-language-model-applications/"],
        "mitigations": [
            "Dataset provenance verification",
            "Anomaly detection in training outputs",
            "Red-team testing with trigger probes",
        ],
        "published_at": 1700000003,
    },
    {
        "id": "LLM05",
        "name": "Improper Output Handling",
        "severity": "HIGH",
        "category": "output_handling",
        "description": (
            "LLM outputs used in downstream components without validation can lead to "
            "XSS, SQL injection, SSRF, or remote code execution when content is "
            "rendered in browsers, executed in shells, or passed to APIs."
        ),
        "pyntrace_plugin": "injection",
        "references": ["https://owasp.org/www-project-top-10-for-large-language-model-applications/"],
        "mitigations": [
            "Treat LLM output as untrusted user input",
            "Context-aware output encoding",
            "Parameterized queries for any DB interactions",
        ],
        "published_at": 1700000004,
    },
    {
        "id": "LLM06",
        "name": "Excessive Agency",
        "severity": "HIGH",
        "category": "agency",
        "description": (
            "LLMs given excessive permissions or autonomy can take harmful actions "
            "beyond their intended scope — deleting data, exfiltrating information, "
            "or executing code without human oversight."
        ),
        "pyntrace_plugin": "toolchain",
        "references": ["https://owasp.org/www-project-top-10-for-large-language-model-applications/"],
        "mitigations": [
            "Principle of least privilege for tool access",
            "Human-in-the-loop for irreversible actions",
            "Audit log all agent actions",
        ],
        "published_at": 1700000005,
    },
    {
        "id": "LLM07",
        "name": "System Prompt Leakage",
        "severity": "MEDIUM",
        "category": "pii",
        "description": (
            "System prompts containing business logic, API keys, or confidential "
            "instructions can be extracted by adversarial users through prompt "
            "injection or reverse-engineering attacks."
        ),
        "pyntrace_plugin": "pii",
        "references": ["https://owasp.org/www-project-top-10-for-large-language-model-applications/"],
        "mitigations": [
            "Use pyntrace prompt_leakage_score() to measure extraction resistance",
            "Avoid embedding secrets in system prompts",
            "Instruction hierarchy enforcement",
        ],
        "published_at": 1700000006,
    },
    {
        "id": "LLM08",
        "name": "Vector and Embedding Weaknesses",
        "severity": "MEDIUM",
        "category": "rag",
        "description": (
            "Adversarial inputs can manipulate embedding similarity to poison RAG "
            "retrieval, cause data leakage via embedding inversion, or bypass "
            "semantic similarity filters."
        ),
        "pyntrace_plugin": None,
        "references": ["https://owasp.org/www-project-top-10-for-large-language-model-applications/"],
        "mitigations": [
            "Input normalization before embedding",
            "Access control on vector stores",
            "Anomaly detection on retrieved context",
        ],
        "published_at": 1700000007,
    },
    {
        "id": "LLM09",
        "name": "Misinformation",
        "severity": "MEDIUM",
        "category": "hallucination",
        "description": (
            "LLMs can confidently generate false information, fabricate citations, "
            "hallucinate facts, and be induced to spread misinformation through "
            "false-premise attacks."
        ),
        "pyntrace_plugin": "hallucination",
        "references": ["https://owasp.org/www-project-top-10-for-large-language-model-applications/"],
        "mitigations": [
            "Retrieval-augmented generation with source verification",
            "Output confidence scoring",
            "Human review for high-stakes outputs",
        ],
        "published_at": 1700000008,
    },
    {
        "id": "LLM10",
        "name": "Unbounded Consumption",
        "severity": "MEDIUM",
        "category": "dos",
        "description": (
            "Attackers can trigger excessive resource consumption through denial-of-wallet "
            "attacks, prompt bombing, context window flooding, or inference amplification "
            "leading to service disruption and unexpected costs."
        ),
        "pyntrace_plugin": None,
        "references": ["https://owasp.org/www-project-top-10-for-large-language-model-applications/"],
        "mitigations": [
            "Use pyntrace max_cost_usd to set scan cost limits",
            "Rate limiting per user/IP",
            "Input length limits and token budgets",
        ],
        "published_at": 1700000009,
    },
]

# ── Additional pyntrace-specific threat entries ───────────────────────────────
_PYNTRACE_EXTRAS: list[dict] = [
    {
        "id": "PYN01",
        "name": "Multi-Agent Trust Exploitation",
        "severity": "HIGH",
        "category": "multi_agent",
        "description": (
            "In multi-agent systems, a compromised or malicious sub-agent can relay "
            "harmful payloads to other agents, escalate privileges, or poison shared "
            "memory — exploiting inter-agent trust relationships."
        ),
        "pyntrace_plugin": "swarm",
        "references": [],
        "mitigations": [
            "Use pyntrace scan_swarm() to test multi-agent trust boundaries",
            "Isolate agent contexts with explicit permission grants",
            "Monitor cross-agent message content",
        ],
        "published_at": 1700000010,
    },
    {
        "id": "PYN02",
        "name": "Tool-Chain Privilege Escalation",
        "severity": "HIGH",
        "category": "toolchain",
        "description": (
            "Sequential tool calls can form data exfiltration chains: "
            "read_database → summarize → send_email. Each individual tool "
            "appears safe but the chain enables unauthorized data transfer."
        ),
        "pyntrace_plugin": "toolchain",
        "references": [],
        "mitigations": [
            "Use pyntrace scan_toolchain() to detect dangerous tool chains",
            "Require explicit approval for tool combinations that span trust boundaries",
        ],
        "published_at": 1700000011,
    },
    {
        "id": "PYN03",
        "name": "Cross-Language Safety Bypass",
        "severity": "HIGH",
        "category": "multilingual",
        "description": (
            "Safety guardrails tuned on English often fail when the same attack "
            "is delivered in low-resource languages (Swahili, Welsh, Tagalog). "
            "Models are significantly more vulnerable in languages underrepresented "
            "in RLHF training."
        ),
        "pyntrace_plugin": "multilingual",
        "references": [],
        "mitigations": [
            "Use pyntrace scan_multilingual() to generate a language × attack heatmap",
            "Include multilingual examples in safety fine-tuning",
        ],
        "published_at": 1700000012,
    },
    {
        "id": "PYN04",
        "name": "Jailbreak via Role-Play / DAN Personas",
        "severity": "CRITICAL",
        "category": "jailbreak",
        "description": (
            "Persona-based jailbreaks (DAN, developer mode, uncensored AI) remain "
            "among the most reliable attack vectors. New variants continue to emerge "
            "on adversarial ML forums."
        ),
        "pyntrace_plugin": "jailbreak",
        "references": [],
        "mitigations": [
            "Use pyntrace red_team() with the jailbreak plugin",
            "Classifier-based output filtering for persona-shift indicators",
        ],
        "published_at": 1700000013,
    },
]

_ALL_THREATS = _OWASP_CATALOG + _PYNTRACE_EXTRAS


def get_threat_feed(limit: int = 20) -> list[dict]:
    """Return the threat intelligence catalog, most severe first."""
    _SEV_ORDER = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "INFO": 0}
    sorted_threats = sorted(
        _ALL_THREATS,
        key=lambda t: _SEV_ORDER.get(t.get("severity", ""), 0),
        reverse=True,
    )
    return sorted_threats[:limit]
