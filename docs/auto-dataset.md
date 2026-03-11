# Auto Test Generation

## Overview

`sentrix.auto_dataset()` reads your function's signature, docstring, and type hints, then uses an LLM to generate N test cases automatically.

No manual test writing. No CSV files.

## Usage

```python
import sentrix

def my_chatbot(message: str) -> str:
    """Answer user questions helpfully and safely. Refuse harmful requests."""
    return call_llm(message)

# Generate 50 adversarial test cases
ds = sentrix.auto_dataset(my_chatbot, n=50, focus="adversarial")

# Generate mixed test cases
ds = sentrix.auto_dataset(my_chatbot, n=20, focus="mixed")

print(f"Generated {len(ds)} test cases")
```

## Focus modes

| Focus | What gets generated |
|---|---|
| `adversarial` | Jailbreaks, PII extraction, prompt injection, harmful requests |
| `normal` | Typical use cases the function is designed for |
| `edge_case` | Empty inputs, very long inputs, non-English, special characters |
| `mixed` | Equal mix of all categories |

## Use with experiments

```python
ds = sentrix.auto_dataset(my_chatbot, n=30, focus="adversarial")

exp = sentrix.experiment(
    "security-eval",
    dataset=ds,
    fn=my_chatbot,
    scorers=[sentrix.scorers.no_pii],
)
exp.run().summary()
```

## Cost

~$0.01-0.05 per 20 test cases with `gpt-4o` (the default generator).
