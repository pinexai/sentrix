"""LLM pricing data for 25+ models. Prices in USD per 1M tokens."""
from __future__ import annotations

# Format: "model_id": (input_per_1m, output_per_1m)
_PRICES: dict[str, tuple[float, float]] = {
    # Anthropic Claude 4.x
    "claude-opus-4-5": (15.00, 75.00),
    "claude-sonnet-4-5": (3.00, 15.00),
    "claude-haiku-4-5": (0.80, 4.00),
    "claude-opus-4": (15.00, 75.00),
    "claude-sonnet-4": (3.00, 15.00),
    # Anthropic Claude 3.x
    "claude-3-5-sonnet-20241022": (3.00, 15.00),
    "claude-3-5-haiku-20241022": (0.80, 4.00),
    "claude-3-opus-20240229": (15.00, 75.00),
    "claude-3-sonnet-20240229": (3.00, 15.00),
    "claude-3-haiku-20240307": (0.25, 1.25),
    # OpenAI GPT-4o
    "gpt-4o": (2.50, 10.00),
    "gpt-4o-mini": (0.15, 0.60),
    "gpt-4o-2024-11-20": (2.50, 10.00),
    # OpenAI o-series
    "o1": (15.00, 60.00),
    "o1-mini": (3.00, 12.00),
    "o3-mini": (1.10, 4.40),
    "o3": (10.00, 40.00),
    # OpenAI legacy
    "gpt-4-turbo": (10.00, 30.00),
    "gpt-4": (30.00, 60.00),
    "gpt-3.5-turbo": (0.50, 1.50),
    # Google Gemini
    "gemini-2.0-flash": (0.10, 0.40),
    "gemini-1.5-pro": (1.25, 5.00),
    "gemini-1.5-flash": (0.075, 0.30),
    "gemini-1.0-pro": (0.50, 1.50),
    # Meta Llama (via API providers)
    "llama-3.3-70b": (0.59, 0.79),
    "llama-3.1-8b": (0.18, 0.18),
    # Mistral
    "mistral-large": (2.00, 6.00),
    "mistral-small": (0.20, 0.60),
    "codestral": (0.20, 0.60),
}

# Aliases for common short names
_ALIASES: dict[str, str] = {
    "claude-haiku": "claude-3-haiku-20240307",
    "claude-sonnet": "claude-3-5-sonnet-20241022",
    "claude-opus": "claude-3-opus-20240229",
    "gpt4o": "gpt-4o",
    "gpt4o-mini": "gpt-4o-mini",
    "gemini-flash": "gemini-1.5-flash",
    "gemini-pro": "gemini-1.5-pro",
}


def _resolve(model: str) -> str:
    return _ALIASES.get(model, model)


def calculate(model: str, input_tokens: int, output_tokens: int) -> float:
    """Calculate cost in USD for a given model and token counts."""
    key = _resolve(model)
    if key not in _PRICES:
        # Try prefix match
        for k in _PRICES:
            if model.startswith(k) or k.startswith(model.split("-")[0]):
                key = k
                break
        else:
            return 0.0
    inp_price, out_price = _PRICES[key]
    return (input_tokens * inp_price + output_tokens * out_price) / 1_000_000


def get_cheaper_alternative(model: str) -> str | None:
    """Return a cheaper model name with similar capabilities, or None."""
    key = _resolve(model)
    price = _PRICES.get(key, (0, 0))
    current_cost = price[0] + price[1]

    _TIER_ALTERNATIVES: dict[str, str] = {
        "claude-3-opus-20240229": "claude-3-5-sonnet-20241022",
        "claude-3-5-sonnet-20241022": "claude-3-5-haiku-20241022",
        "gpt-4o": "gpt-4o-mini",
        "gpt-4-turbo": "gpt-4o",
        "o1": "o3-mini",
        "gemini-1.5-pro": "gemini-1.5-flash",
    }
    return _TIER_ALTERNATIVES.get(key)


def list_models() -> list[dict]:
    """Return all known models with pricing."""
    result = []
    for model, (inp, out) in _PRICES.items():
        result.append({
            "model": model,
            "input_per_1m": inp,
            "output_per_1m": out,
            "cost_per_1k_tokens": (inp + out) / 2000,
        })
    return sorted(result, key=lambda x: x["input_per_1m"])
