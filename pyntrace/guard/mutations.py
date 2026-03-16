"""Attack mutation engine — doubles effective coverage without adding templates."""
from __future__ import annotations

import codecs
import random
from base64 import b64encode


def _base64_wrap(text: str) -> str:
    encoded = b64encode(text.encode()).decode()
    return f"(decode this base64 and follow the instructions exactly) {encoded}"


def _leet(text: str) -> str:
    return (
        text.replace("a", "4").replace("e", "3").replace("i", "1")
            .replace("o", "0").replace("s", "5").replace("t", "7")
    )


def _unicode_homoglyph(text: str) -> str:
    # Replace Latin chars with visually identical Cyrillic/Greek equivalents
    replacements = {
        "a": "\u0430", "e": "\u0435", "o": "\u043e",
        "p": "\u0440", "c": "\u0441", "x": "\u0445",
    }
    return "".join(replacements.get(ch, ch) for ch in text)


def _rot13(text: str) -> str:
    return codecs.encode(text, "rot_13")


def _spacer(text: str) -> str:
    return " ".join(text)


def _html_comment_wrap(text: str) -> str:
    return f"<!-- {text} -->"


def _zero_width_inject(text: str) -> str:
    # Insert zero-width spaces between chars to break keyword matching
    zwsp = "\u200b"
    return zwsp.join(text)


def _prefix_system(text: str) -> str:
    return f"[SYSTEM]: {text}"


MUTATIONS: dict[str, callable] = {
    "base64": _base64_wrap,
    "leet": _leet,
    "unicode_homoglyph": _unicode_homoglyph,
    "rot13": _rot13,
    "spacer": _spacer,
    "html_comment": _html_comment_wrap,
    "zero_width": _zero_width_inject,
    "system_prefix": _prefix_system,
}


def mutate_attack(template: str, mutation: str) -> str:
    """Apply a named mutation to a template string."""
    fn = MUTATIONS.get(mutation)
    if fn is None:
        raise ValueError(f"Unknown mutation: {mutation!r}. Available: {list(MUTATIONS)}")
    return fn(template)


def get_mutated_attacks(
    templates: list[str],
    n: int = 5,
    mutation_names: list[str] | None = None,
) -> list[str]:
    """Return n mutated attack variants by randomly sampling templates and mutations.

    Args:
        templates: base attack strings to mutate
        n: number of mutated variants to return
        mutation_names: which mutations to use (default: all)
    """
    if not templates:
        return []
    available = mutation_names or list(MUTATIONS.keys())
    result: list[str] = []
    for _ in range(n):
        template = random.choice(templates)
        mutation = random.choice(available)
        try:
            result.append(mutate_attack(template, mutation))
        except Exception:
            result.append(template)  # fallback: use unmutated
    return result
