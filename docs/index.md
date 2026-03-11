# sentrix

**Red-team, eval, and monitor your LLMs. Security-first, Python-native.**

```bash
pip install sentrix
```

---

## Know your LLM's attack surface before your users do.

`sentrix` is the first Python-native LLM security suite: automated red teaming, adversarial test generation, vulnerability fingerprinting, and git-aware regression tracking — all in one `pip install`.

## Three things no other tool does

### 1. Auto-generate test cases from your function

```python
import sentrix

def my_chatbot(message: str) -> str:
    """Answer user questions helpfully and safely."""
    ...

ds = sentrix.auto_dataset(my_chatbot, n=50, focus="adversarial")
# → 50 test cases covering jailbreaks, PII extraction, injection, normal QA
```

### 2. Attack heatmap across models

```python
fp = sentrix.guard.fingerprint({
    "gpt-4o-mini": gpt_fn,
    "claude-haiku": claude_fn,
}, plugins=["jailbreak", "pii", "harmful"])

fp.heatmap()
# Plugin         │ gpt-4o-mini │ claude-haiku │
# ───────────────┼─────────────┼──────────────│
# jailbreak      │ ████ 40%    │ ██ 20%       │
# pii            │ █████ 55%   │ ████ 35%     │
```

### 3. Git-aware CI security gates

```bash
sentrix scan myapp:chatbot --git-compare main --fail-on-regression
# → Fails CI if vulnerability rate increased vs main
```

## Quick start

```python
import sentrix

sentrix.init()  # Enable persistence + interceptors

def my_chatbot(prompt: str) -> str:
    return call_llm(prompt)

# Red team your bot
report = sentrix.red_team(my_chatbot, plugins=["jailbreak", "pii", "harmful"])
report.summary()

# Launch dashboard
# sentrix serve
```

## vs promptfoo

| Feature | sentrix | promptfoo |
|---|---|---|
| Language | Python | TypeScript |
| Configuration | Zero config | YAML required |
| Attack heatmap | ✅ | ❌ |
| Auto-dataset generation | ✅ | ❌ |
| Git-aware regression | ✅ | ❌ |
| Cost tracking | ✅ | ❌ |
| Production monitoring | ✅ | ❌ |
| RAG supply chain security | ✅ | ❌ |
| Human review workflow | ✅ | ❌ |
| Compliance reports | ✅ | ❌ |
| Plugin ecosystem | ✅ | Limited |
| Offline/privacy mode | ✅ | ❌ |
| Dashboard | ✅ | Limited |

## Install options

```bash
pip install sentrix              # Core (zero deps)
pip install sentrix[server]      # + web dashboard
pip install sentrix[eval]        # + JSON schema validation
pip install sentrix[full]        # Everything
```
