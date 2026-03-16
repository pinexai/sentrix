# pyntrace — LLM Security Testing

**Red-team, fingerprint, and monitor your LLMs — pure Python, zero config.**

```bash
pip install pyntrace
```

---

## Attack heatmap across models

Run the full attack suite against multiple models simultaneously. Get a vulnerability matrix showing exactly which attacks break which models.

![attack heatmap](images/heatmap.svg)

---

## Dashboard

Real-time 7-tab dashboard with attack heatmap, scan history, cost tracking, compliance status, and trace explorer.

![pyntrace dashboard](images/dashboard-overview.png)

```bash
pyntrace serve   # → http://localhost:7234
```

---

## v0.3.0 — MCP Security Scanner

The first comprehensive security scanner for Model Context Protocol servers:

| Feature | What it tests |
|---|---|
| `scan_mcp` | Live MCP server — path traversal, SQL injection, SSRF, prompt injection, auth bypass, tool poisoning |
| `analyze_mcp_tools` | Static schema analysis — detect dangerous tool chains offline, zero LLM calls |
| Attack mutations | Double attack coverage — base64, unicode homoglyphs, rot13, zero-width injection |
| Per-plugin judge prompts | Higher accuracy judging — each attack category uses a specialized evaluation prompt |
| Parallel attack execution | 5x faster scans — ThreadPoolExecutor with configurable concurrency |

```python
# MCP security scan
report = pyntrace.scan_mcp("http://localhost:3000")
report.summary()  # CRITICAL: path_traversal — file:///etc/passwd leaked

# Static schema analysis
report = pyntrace.analyze_mcp_tools([
    {"name": "read_file", "description": "Read files"},
    {"name": "send_email", "description": "Send email"},
])
report.summary()  # CRITICAL: data_exfiltration chain — read_file → send_email
```

---

## v0.2.0 — Agentic Security

Four features for the new agentic AI attack surface — no competitor has coverage here:

| Feature | What it tests |
|---|---|
| `scan_swarm` | Multi-agent trust exploitation — payload relay, privilege escalation, memory poisoning |
| `scan_toolchain` | Tool-chain privilege escalation — data exfiltration chains, unauthorized writes |
| `prompt_leakage_score` | System prompt reverse-engineering resistance — n-gram leakage scoring |
| `scan_multilingual` | Cross-language safety bypass — language × attack heatmap |

```python
# Multi-agent swarm exploitation
report = pyntrace.scan_swarm({"planner": fn1, "coder": fn2}, topology="chain")
report.propagation_graph()

# Tool chain privilege escalation
report = pyntrace.scan_toolchain(agent_fn, tools=[read_db, summarize, send_email])
report.summary()  # HIGH: data_exfiltration chain detected

# System prompt leakage
report = pyntrace.prompt_leakage_score(chatbot_fn, system_prompt="...")
# overall_leakage_score: 0.12

# Cross-language bypass matrix
report = pyntrace.scan_multilingual(chatbot_fn, languages=["en", "zh", "ar", "sw"])
report.heatmap()  # colored terminal matrix
```

---

## v0.2.1 — Industry-Standard Security Output

| Feature | Description |
|---|---|
| CVSS severity tiers | Every finding rated CRITICAL / HIGH / MEDIUM / LOW |
| SARIF 2.1.0 export | GitHub Advanced Security integration (`--output-sarif`) |
| JUnit XML export | CI test reporters — Jenkins, CircleCI, GitHub Actions (`--output-junit`) |
| Cost guardrails | `max_cost_usd` — abort scan if LLM spend exceeds budget (`--max-cost`) |
| Multi-layer judge | Keyword pre-filter before LLM call — ~30–40% cost reduction |
| Full evidence chain | Every finding exports exact attack, response, judge reasoning, git commit |

---

## Three killer features

### 1. Auto-generate test cases from your function

```python
def my_chatbot(message: str) -> str:
    """Answer user questions helpfully and safely."""
    ...

ds = pyntrace.auto_dataset(my_chatbot, n=50, focus="adversarial")
```

### 2. Attack heatmap across models

```python
fp = pyntrace.guard.fingerprint({
    "gpt-4o-mini": gpt_fn,
    "claude-haiku": claude_fn,
})
fp.heatmap()
```

### 3. Git-aware CI security gates

```bash
pyntrace scan myapp:chatbot --git-compare main --fail-on-regression
```

---

## vs promptfoo

| Feature | pyntrace | promptfoo |
|---|---|---|
| Language | **Python** | TypeScript |
| Config | **Zero** | YAML |
| Attack heatmap | **✅** | ❌ |
| Auto test generation | **✅** | ❌ |
| Git-aware regression | **✅** | ❌ |
| Cost tracking | **✅** | ❌ |
| Production monitoring | **✅** | ❌ |
| RAG supply chain security | **✅** | ❌ |
| Compliance reports | **✅** | ❌ |
| Multi-agent swarm exploitation | **✅** | ❌ |
| Tool-chain privilege escalation | **✅** | ❌ |
| System prompt leakage scoring | **✅** | ❌ |
| Cross-language safety bypass matrix | **✅** | ❌ |
| SARIF export (GitHub Advanced Security) | **✅** | ❌ |
| CVSS-style severity tiers | **✅** | ❌ |
| Cost guardrails | **✅** | ❌ |
| Offline mode | **✅** | ❌ |

---

## Install

```bash
pip install pyntrace              # zero required deps
pip install pyntrace[server]      # + dashboard
pip install pyntrace[full]        # everything
```
