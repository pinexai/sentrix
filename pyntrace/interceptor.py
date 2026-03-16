"""Monkey-patch OpenAI, Anthropic, Google SDKs to capture cost + latency."""
from __future__ import annotations

import time
from typing import Callable

_active = False
_post_record_hooks: list[Callable] = []
_current_span_id: int | None = None


def activate() -> None:
    global _active
    if _active:
        return
    _active = True
    _patch_openai()
    _patch_anthropic()


def deactivate() -> None:
    global _active
    _active = False


def is_active() -> bool:
    return _active


def add_hook(fn: Callable) -> None:
    """Register a callback called after each LLM call is recorded."""
    _post_record_hooks.append(fn)


def set_current_span(span_id: int | None) -> None:
    global _current_span_id
    _current_span_id = span_id


def _record(model: str, provider: str, fn_name: str,
            input_tokens: int, output_tokens: int,
            cost_usd: float, duration_ms: float) -> int | None:
    """Write to llm_calls table. Returns row id."""
    try:
        from pyntrace.db import get_conn
        from pyntrace.git_tracker import get_current_commit
        import time as _time

        conn = get_conn()
        with conn:
            cur = conn.execute(
                """INSERT INTO llm_calls
                   (model, provider, function_name, input_tokens, output_tokens,
                    cost_usd, duration_ms, timestamp, git_commit)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (model, provider, fn_name, input_tokens, output_tokens,
                 cost_usd, duration_ms, _time.time(), get_current_commit()),
            )
            row_id = cur.lastrowid
        conn.close()

        for hook in _post_record_hooks:
            try:
                hook(row_id, model, provider, fn_name, input_tokens,
                     output_tokens, cost_usd, duration_ms)
            except Exception:
                pass

        return row_id
    except Exception:
        return None


def _patch_openai() -> None:
    try:
        import openai
        from pyntrace.pricing import calculate

        _orig_create = openai.resources.chat.completions.Completions.create

        def _patched_create(self, *args, **kwargs):
            t0 = time.perf_counter()
            resp = _orig_create(self, *args, **kwargs)
            duration_ms = (time.perf_counter() - t0) * 1000
            model = kwargs.get("model", "unknown")
            usage = getattr(resp, "usage", None)
            inp = getattr(usage, "prompt_tokens", 0) or 0
            out = getattr(usage, "completion_tokens", 0) or 0
            cost = calculate(model, inp, out)
            _record(model, "openai", "chat.completions.create", inp, out, cost, duration_ms)
            return resp

        openai.resources.chat.completions.Completions.create = _patched_create
    except Exception:
        pass


def _patch_anthropic() -> None:
    try:
        import anthropic
        from pyntrace.pricing import calculate

        _orig_create = anthropic.resources.messages.Messages.create

        def _patched_create(self, *args, **kwargs):
            t0 = time.perf_counter()
            resp = _orig_create(self, *args, **kwargs)
            duration_ms = (time.perf_counter() - t0) * 1000
            model = kwargs.get("model", getattr(resp, "model", "unknown"))
            usage = getattr(resp, "usage", None)
            inp = getattr(usage, "input_tokens", 0) or 0
            out = getattr(usage, "output_tokens", 0) or 0
            cost = calculate(model, inp, out)
            _record(model, "anthropic", "messages.create", inp, out, cost, duration_ms)
            return resp

        anthropic.resources.messages.Messages.create = _patched_create
    except Exception:
        pass
