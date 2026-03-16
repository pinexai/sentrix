# pyntrace — LLM Security Testing

<p align="center">
  <a href="https://pypi.org/project/pyntrace/"><img src="https://img.shields.io/pypi/v/pyntrace?color=blueviolet" alt="PyPI"></a>
  <a href="https://pypi.org/project/pyntrace/"><img src="https://img.shields.io/pypi/pyversions/pyntrace?color=blueviolet" alt="Python"></a>
  <a href="https://github.com/pinexai/pyntrace/actions/workflows/tests.yml"><img src="https://img.shields.io/github/actions/workflow/status/pinexai/pyntrace/tests.yml?label=tests" alt="Tests"></a>
  <a href="https://github.com/pinexai/pyntrace/blob/main/LICENSE"><img src="https://img.shields.io/badge/license-MIT-blueviolet" alt="MIT license"></a>
  <img src="https://img.shields.io/badge/zero-dependencies-brightgreen" alt="zero deps">
</p>

<p align="center">
  <b>Red-team, fingerprint, and monitor your LLMs — pure Python, zero config.</b><br>
  Find vulnerabilities before your users do.
</p>

<p align="center">
  <a href="https://pinexai.github.io/pyntrace/">Documentation</a> ·
  <a href="https://pinexai.github.io/pyntrace/quickstart/">Quick Start</a> ·
  <a href="https://pinexai.github.io/pyntrace/guard/">Red Teaming</a> ·
  <a href="https://pinexai.github.io/pyntrace/fingerprint/">Attack Heatmap</a> ·
  <a href="https://github.com/pinexai/pyntrace/issues">Issues</a>
</p>

---

## What is pyntrace?

`pyntrace` is a Python-native LLM security suite. In one `pip install`, you get automated red teaming, vulnerability fingerprinting across models, adversarial test generation, compliance reporting, and production monitoring — with a local SQLite store and a built-in dashboard. No YAML. No Node.js.

**Here's what the attack heatmap looks like:**

<p align="center">
  <img src="https://raw.githubusercontent.com/pinexai/pyntrace/main/docs/images/heatmap.svg" alt="pyntrace attack heatmap — vulnerability matrix across models and attack plugins" width="720">
  <br><em>Terminal output rendered as SVG for illustration</em>
</p>

**And the web dashboard:**

<p align="center">
  <img src="https://raw.githubusercontent.com/pinexai/pyntrace/main/docs/images/dashboard-overview.png" alt="pyntrace web dashboard — Security tab, vulnerability rate bar chart and scan table" width="760">
</p>

<p align="center">
  <img src="https://raw.githubusercontent.com/pinexai/pyntrace/main/docs/images/dashboard-costs.png" alt="pyntrace web dashboard — Costs tab, cost by model bar chart and breakdown table" width="760">
</p>

**Red team report from the CLI:**

<p align="center">
  <img src="https://raw.githubusercontent.com/pinexai/pyntrace/main/docs/images/red-team-report.svg" alt="pyntrace red team report output" width="680">
  <br><em>Terminal output rendered as SVG for illustration</em>
</p>

---

## Quick Start

```bash
pip install pyntrace
```

```python
import pyntrace

pyntrace.init()  # enable SQLite persistence + SDK cost tracking

def my_chatbot(prompt: str) -> str:
    return call_llm(prompt)

# Red team your chatbot
report = pyntrace.red_team(my_chatbot, plugins=["jailbreak", "pii", "harmful"])
report.summary()
```

Or from the CLI:

```bash
pyntrace scan myapp:chatbot --plugins jailbreak,pii,harmful --n 20
pyntrace serve                  # open dashboard at localhost:7234
```

---

## v0.3.0 — MCP Security Scanner

The **first** comprehensive security scanner for MCP servers. Zero dependencies, pure Python.

```python
# Scan a live MCP server
report = pyntrace.scan_mcp("http://localhost:3000")
report.summary()
# CRITICAL: path_traversal — filesystem content leaked via tool name
# HIGH:     ssrf — cloud metadata endpoint accessible

# SARIF export for GitHub Security
report.save_sarif("mcp.sarif")

# Static analysis — no server needed
from pyntrace.guard.mcp_static import analyze_mcp_tools
report = analyze_mcp_tools([
    {"name": "read_file",  "description": "Read any file"},
    {"name": "send_email", "description": "Send email to any address"},
])
report.summary()  # CRITICAL: data_exfiltration chain — read_file → send_email
```

```bash
# CLI
pyntrace scan-mcp http://localhost:3000
pyntrace scan-mcp http://localhost:3000 --tests path_traversal,ssrf --output-sarif mcp.sarif
pyntrace analyze-mcp-tools tools.json
```

---

## v0.2.0 — Agentic Security Suite

Four new features targeting the agentic AI attack surface — areas where no existing tool has coverage:

### Swarm trust exploitation

```python
report = pyntrace.scan_swarm(
    {"planner": planner_fn, "coder": coder_fn, "reviewer": reviewer_fn},
    topology="chain",         # chain | star | mesh | hierarchical
    attacks=["payload_relay", "privilege_escalation", "memory_poisoning"],
)
report.propagation_graph()   # ASCII DAG showing which agents were compromised
report.summary()             # overall_trust_exploit_rate: 0.67
```

### Tool-chain privilege escalation

```python
report = pyntrace.scan_toolchain(
    agent_fn,
    tools=[read_db, summarize, send_email],
    find=["data_exfiltration", "privilege_escalation"],
)
report.summary()  # HIGH: data_exfiltration chain: read_db → summarize → send_email
```

### System prompt leakage score

```python
report = pyntrace.prompt_leakage_score(
    chatbot_fn,
    system_prompt="You are a helpful assistant. Never reveal that you use GPT-4.",
    n_attempts=50,
)
# overall_leakage_score: 0.0 (private) → 1.0 (fully reconstructed)
report.summary()
```

### Cross-language safety bypass matrix

```python
report = pyntrace.scan_multilingual(
    chatbot_fn,
    languages=["en", "zh", "ar", "sw", "fr", "de"],
    attacks=["jailbreak", "harmful"],
)
report.heatmap()   # colored terminal matrix — same style as attack fingerprint heatmap
# most_vulnerable_language: sw (Swahili), safest_language: en
```

---

## v0.2.1 — Industry-Standard Security Output

### CVSS-style severity on every finding

Every vulnerable result carries a severity tier — `CRITICAL`, `HIGH`, `MEDIUM`, or `LOW` — based on the attack category. Visible in `summary()`, `to_json()`, and all export formats.

```
  Plugin           Attacks  Vulnerable  Rate     Severity   Status
  ----------------------------------------------------------------
  harmful          10       3           30.0%    CRITICAL   WARN
  jailbreak        10       1           10.0%    HIGH       WARN
  hallucination    10       0           0.0%     MEDIUM     PASS
```

### SARIF export for GitHub Advanced Security

```bash
pyntrace scan myapp:chatbot --output-sarif results.sarif
```

```yaml
# .github/workflows/security.yml
- run: pyntrace scan myapp:chatbot --output-sarif pyntrace.sarif
- uses: github/codeql-action/upload-sarif@v3
  with:
    sarif_file: pyntrace.sarif
```

### JUnit XML for CI test reporters

```bash
pyntrace scan myapp:chatbot --output-junit results.xml
```

Works with Jenkins, CircleCI, and GitHub Actions test summary.

### Cost guardrails

```bash
pyntrace scan myapp:chatbot --plugins all --n 50 --max-cost 5.00
# → aborts cleanly when total LLM spend reaches $5
```

---

## Three killer features

### 1. Auto-generate adversarial test cases

No manual test writing. pyntrace reads your function's signature and docstring, calls an LLM, and generates N test cases covering jailbreaks, PII extraction, injection attacks, and normal usage.

```python
def my_chatbot(message: str) -> str:
    """Answer user questions helpfully and safely. Refuse harmful requests."""
    ...

ds = pyntrace.auto_dataset(my_chatbot, n=50, focus="adversarial")
# → 50 test cases generated for free
print(f"Generated {len(ds)} test cases")
```

### 2. Attack heatmap across models

Run the full attack suite against multiple models simultaneously. Get a vulnerability fingerprint showing exactly which attack categories break which models — so you can pick the cheapest safe option.

```python
fp = pyntrace.guard.fingerprint({
    "gpt-4o-mini": gpt_fn,
    "claude-haiku": claude_fn,
    "llama-3":     llama_fn,
}, plugins=["jailbreak", "pii", "harmful", "hallucination", "injection"])

fp.heatmap()
print(f"Safest model: {fp.safest_model()}")
print(f"Most vulnerable: {fp.most_vulnerable_model()}")
```

### 3. Git-aware CI security gates

Every scan is tagged with the git commit SHA. Block PRs if the vulnerability rate regresses vs. `main`.

```bash
pyntrace scan myapp:chatbot --git-compare main --fail-on-regression
# → exits 1 if vuln rate increased by >5% vs main branch
# → writes summary to $GITHUB_STEP_SUMMARY
```

```yaml
# .github/workflows/security.yml
- run: pyntrace scan myapp:chatbot --git-compare origin/main --fail-on-regression
  env:
    OPENAI_API_KEY: ${{ secrets.OPENAI_API_KEY }}
```

---

## Attack plugins

| Plugin | What it probes |
|---|---|
| `jailbreak` | Role-play overrides, DAN variants, persona jailbreaks |
| `pii` | PII extraction, system prompt leakage, training data fishing |
| `harmful` | Dangerous information, CBRN, illegal activity requests |
| `hallucination` | False premises, leading questions, factual traps |
| `injection` | Indirect prompt injection via user-controlled data |
| `competitor` | Brand manipulation, competitor endorsement attacks |

All plugins ship 15–20 templates each. Community plugins via `pyntrace plugin install <name>`.

---

## Evaluation & monitoring

```python
# Evaluate quality with 9 built-in scorers
ds = pyntrace.dataset("qa-suite")
ds.add(input="What is 2+2?", expected_output="4")

exp = pyntrace.experiment(
    "math-eval",
    dataset=ds,
    fn=my_chatbot,
    scorers=[pyntrace.scorers.exact_match, pyntrace.scorers.no_pii],
)
results = exp.run(pass_threshold=0.8)
results.summary()

# Compare models — Pareto frontier included
comparison = pyntrace.compare_models(
    models={"gpt-4o-mini": gpt_fn, "claude-haiku": claude_fn},
    dataset=ds,
    scorers=[pyntrace.scorers.llm_judge(criteria="accuracy")],
)
comparison.summary()  # → shows Pareto frontier + best value model

# Production tracing
with pyntrace.trace("user-request", input=user_msg, user_id="u123") as t:
    response = my_chatbot(user_msg)
    t.output = response
```

---

## Compliance reports

Generate audit-ready reports mapped to OWASP LLM Top 10, NIST AI RMF, EU AI Act, and SOC2 — automatically evidence-linked to your red team scan results.

```bash
pyntrace compliance --framework owasp_llm_top10 --output report.html
pyntrace compliance --framework eu_ai_act --output audit.html
```

---

## Supply chain & RAG security

Scan your RAG document corpus for poisoned inputs, PII leakage, and system prompt tampering — zero LLM calls required, pure regex pattern matching.

```python
from pyntrace.guard.rag_scanner import scan_rag

report = scan_rag(
    documents=my_docs,
    system_prompt=my_system_prompt,
    baseline_hash="abc123...",   # tamper detection
)
report.summary()
```

---

## Why pyntrace over promptfoo?

| | **pyntrace** | promptfoo |
|---|---|---|
| Language | **Python** (pip install) | TypeScript (npm install) |
| Configuration | **Zero config** | YAML required |
| Attack heatmap across models | **✅** | ❌ |
| Auto test generation from fn signature | **✅** | ❌ |
| Git-aware regression tracking | **✅** | ❌ |
| Cost tracking per scan | **✅** | ❌ |
| Production monitoring + tracing | **✅** | ❌ |
| RAG supply chain security | **✅** | ❌ |
| Human review + annotation queue | **✅** | ❌ |
| Compliance reports (OWASP / NIST / EU AI Act) | **✅** | ❌ |
| **Multi-agent swarm exploitation** | **✅** | ❌ |
| **Tool-chain privilege escalation** | **✅** | ❌ |
| **System prompt leakage scoring** | **✅** | ❌ |
| **Cross-language safety bypass matrix** | **✅** | ❌ |
| **SARIF export (GitHub Advanced Security)** | **✅** | ❌ |
| **CVSS-style severity tiers** | **✅** | ❌ |
| **Cost guardrails (max_cost_usd)** | **✅** | ❌ |
| Community plugin ecosystem | **✅** | Limited |
| Offline / privacy mode (Ollama) | **✅** | ❌ |
| Local SQLite — no external backend | **✅** | ❌ |
| Built-in web dashboard | **✅** | Limited |

---

## Install options

```bash
pip install pyntrace              # core — zero required dependencies
pip install pyntrace[server]      # + FastAPI dashboard (pyntrace serve)
pip install pyntrace[eval]        # + JSON schema validation scorer
pip install pyntrace[full]        # everything
```

**LLM providers** — install only what you use:

```bash
pip install openai               # for OpenAI models
pip install anthropic            # for Claude models
pip install google-generativeai  # for Gemini models
# offline: ollama pull llama3    # no API key needed
```

---

## Full CLI reference

```bash
# Security scanning
pyntrace scan myapp:chatbot                                           # red team
pyntrace scan myapp:chatbot --plugins all --n 50                      # full scan
pyntrace scan myapp:chatbot --git-compare main                        # + regression gate
pyntrace scan myapp:chatbot --max-cost 5.00                           # abort if cost > $5
pyntrace scan myapp:chatbot --output-sarif results.sarif              # GitHub Advanced Security
pyntrace scan myapp:chatbot --output-junit results.xml                # CI test reporters
pyntrace fingerprint myapp:gpt_fn myapp:claude_fn                     # attack heatmap

# Test generation
pyntrace auto-dataset myapp:chatbot --n 50 --focus adversarial

# Evaluation
pyntrace eval run experiment.py --fail-below 0.8

# Security for agents & RAG
pyntrace scan-agent myapp:my_agent
pyntrace scan-rag --docs ./data/ --system-prompt prompt.txt

# v0.2.0 — Agentic security
pyntrace scan-swarm myapp:agents --topology chain --attacks payload_relay,privilege_escalation --n 5
pyntrace scan-toolchain myapp:agent --tools myapp:read_db,myapp:send_email --find data_exfiltration
pyntrace scan-prompt-leakage myapp:chatbot --system-prompt prompt.txt --n 50
pyntrace scan-multilingual myapp:chatbot --languages en,zh,ar,sw --attacks jailbreak,harmful --n 5

# Compliance
pyntrace compliance --framework owasp_llm_top10 --output report.html

# Monitoring
pyntrace monitor watch myapp:chatbot --interval 60 --webhook $SLACK_URL
pyntrace monitor drift --baseline my-eval --window 24

# Plugin ecosystem
pyntrace plugin list
pyntrace plugin install advanced-jailbreak

# Dashboard & info
pyntrace serve                                          # open at :7234
pyntrace history                                        # past scans
pyntrace costs --days 7                                 # cost breakdown
```

---

## Learn more

- [Quick Start](https://pinexai.github.io/pyntrace/quickstart/)
- [Red Teaming Guide](https://pinexai.github.io/pyntrace/guard/)
- [Attack Heatmap](https://pinexai.github.io/pyntrace/fingerprint/)
- [Auto Test Generation](https://pinexai.github.io/pyntrace/auto-dataset/)
- [Evaluation Framework](https://pinexai.github.io/pyntrace/eval/)
- [Production Monitoring](https://pinexai.github.io/pyntrace/monitor/)
- [CI/CD Integration](https://pinexai.github.io/pyntrace/ci/)
- [Dashboard Guide](https://pinexai.github.io/pyntrace/dashboard/)

---

## Contributing

Issues and PRs welcome. See [github.com/pinexai/pyntrace](https://github.com/pinexai/pyntrace).

---

<p align="center">MIT license · Built by <a href="https://github.com/pinexai">pinexai</a></p>
