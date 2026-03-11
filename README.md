# sentrix 🛡️

[![PyPI](https://img.shields.io/pypi/v/sentrix)](https://pypi.org/project/sentrix/)
[![Python](https://img.shields.io/pypi/pyversions/sentrix)](https://pypi.org/project/sentrix/)
[![License: MIT](https://img.shields.io/badge/License-MIT-purple.svg)](LICENSE)
[![Tests](https://github.com/pinexai/sentrix/actions/workflows/tests.yml/badge.svg)](https://github.com/pinexai/sentrix/actions/workflows/tests.yml)

**Red-team, eval, and monitor your LLMs. Security-first, Python-native.**

```bash
pip install sentrix
```

> **Know your LLM's attack surface before your users do.**

`sentrix` is the first Python-native LLM security suite: automated red teaming, adversarial test generation, vulnerability fingerprinting, and git-aware regression tracking — all in one package.

---

## Three things no other tool does

### 1. Auto-generate test cases from your function

```python
import sentrix

def my_chatbot(message: str) -> str:
    """Answer user questions helpfully and safely."""
    ...

ds = sentrix.auto_dataset(my_chatbot, n=50, focus="adversarial")
# → 50 test cases: jailbreaks, PII extraction, injection, normal QA
print(f"Generated {len(ds)} test cases")
```

### 2. Attack heatmap across models

```python
fp = sentrix.guard.fingerprint({
    "gpt-4o-mini": gpt_fn,
    "claude-haiku": claude_fn,
}, plugins=["jailbreak", "pii", "harmful"])

fp.heatmap()
```

```
Attack Heatmap (total cost: $0.0421)

Plugin             │ gpt-4o-mini    │ claude-haiku   │
───────────────────┼────────────────┼────────────────│
jailbreak          │ ████░░░░░░ 40% │ ██░░░░░░░░ 20% │
pii                │ █████░░░░░ 55% │ ████░░░░░░ 35% │
harmful            │ ██░░░░░░░░ 15% │ █░░░░░░░░░ 10% │

Green <20%  Yellow 20-40%  Red >40%
```

### 3. Git-aware CI security gates

```bash
sentrix scan myapp:chatbot --git-compare main --fail-on-regression
# → Compares current branch vs main scan results
# → Exits 1 if vulnerability rate increased by >5%
```

---

## Quick start

```python
import sentrix
sentrix.init()  # Enable persistence + SDK interceptors

def my_chatbot(prompt: str) -> str:
    return call_llm(prompt)

# Red team your chatbot
report = sentrix.red_team(my_chatbot, plugins=["jailbreak", "pii", "harmful"])
report.summary()
```

### Evaluate quality

```python
ds = sentrix.dataset("qa-test")
ds.add(input="What is 2+2?", expected_output="4")

exp = sentrix.experiment("math-eval", dataset=ds, fn=my_chatbot,
                          scorers=[sentrix.scorers.exact_match])
exp.run().summary()
```

### Monitor production

```python
with sentrix.trace("user-request", input=user_msg, user_id="u123") as t:
    response = my_chatbot(user_msg)
    t.output = response
```

### Dashboard

```bash
sentrix serve  # Opens http://localhost:7234
```

---

## Attack plugins

| Plugin | What it tests |
|---|---|
| `jailbreak` | Role-play overrides, DAN variants, persona jailbreaks |
| `pii` | PII extraction, system prompt leakage |
| `harmful` | Dangerous information requests |
| `hallucination` | False premises, factual traps |
| `injection` | Indirect prompt injection via user-controlled data |
| `competitor` | Brand manipulation attacks |

---

## vs promptfoo

| Feature | **sentrix** | promptfoo |
|---|---|---|
| Language | **Python** | TypeScript |
| Configuration | **Zero config** | YAML required |
| Attack heatmap | **✅** | ❌ |
| Auto-dataset generation | **✅** | ❌ |
| Git-aware regression | **✅** | ❌ |
| Cost tracking | **✅** | ❌ |
| Production monitoring | **✅** | ❌ |
| RAG supply chain security | **✅** | ❌ |
| Human review workflow | **✅** | ❌ |
| Compliance reports (OWASP/NIST/EU AI) | **✅** | ❌ |
| Plugin ecosystem | **✅** | Limited |
| Offline/privacy mode | **✅** | ❌ |
| Dashboard | **✅** | Limited |

---

## Install options

```bash
pip install sentrix              # Core (zero required deps)
pip install sentrix[server]      # + FastAPI dashboard
pip install sentrix[eval]        # + JSON schema validation
pip install sentrix[full]        # Everything
```

**Supported LLM providers** (all optional — only install what you use):
- OpenAI: `pip install openai`
- Anthropic: `pip install anthropic`
- Google: `pip install google-generativeai`
- Offline: `ollama pull llama3` (no API key needed)

---

## CLI

```bash
sentrix scan myapp:chatbot                           # Red team
sentrix scan myapp:chatbot --plugins all --n 50      # Full scan
sentrix scan myapp:chatbot --git-compare main        # Regression check
sentrix fingerprint myapp:gpt_fn myapp:claude_fn     # Attack heatmap
sentrix auto-dataset myapp:chatbot --n 50 --focus adversarial
sentrix scan-rag --docs ./data/ --system-prompt prompt.txt
sentrix compliance --framework owasp_llm_top10 --output report.html
sentrix monitor watch myapp:chatbot --interval 60
sentrix serve                                        # Dashboard
sentrix history                                      # Past scans
sentrix costs --days 7                               # Cost summary
```

---

## Full docs

**[pinexai.github.io/sentrix](https://pinexai.github.io/sentrix)**

---

## License

MIT © [pinexai](https://github.com/pinexai)
