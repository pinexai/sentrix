"""Trace and span context managers for production monitoring."""
from __future__ import annotations

import contextvars
import json
import time
import uuid
from contextlib import contextmanager
from dataclasses import dataclass, field
from typing import Any, Generator

_current_trace_id: contextvars.ContextVar[str | None] = contextvars.ContextVar(
    "_current_trace_id", default=None
)
_current_span_id: contextvars.ContextVar[str | None] = contextvars.ContextVar(
    "_current_span_id", default=None
)


@dataclass
class Span:
    id: str
    trace_id: str
    parent_span_id: str | None
    name: str
    span_type: str
    start_time: float
    end_time: float | None = None
    input: Any = None
    output: Any = None
    metadata: dict = field(default_factory=dict)
    model: str | None = None
    input_tokens: int = 0
    output_tokens: int = 0
    cost_usd: float = 0.0
    duration_ms: float = 0.0
    llm_call_id: int | None = None

    def _persist(self) -> None:
        try:
            from pyntrace.db import get_conn
            conn = get_conn()
            with conn:
                conn.execute(
                    """INSERT OR REPLACE INTO spans
                       (id, trace_id, parent_span_id, name, span_type,
                        start_time, end_time, input, output, metadata,
                        model, input_tokens, output_tokens, cost_usd, duration_ms, llm_call_id)
                       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                    (self.id, self.trace_id, self.parent_span_id, self.name, self.span_type,
                     self.start_time, self.end_time,
                     json.dumps(self.input), json.dumps(self.output),
                     json.dumps(self.metadata), self.model,
                     self.input_tokens, self.output_tokens, self.cost_usd,
                     self.duration_ms, self.llm_call_id),
                )
            conn.close()
        except Exception:
            pass


@dataclass
class Trace:
    id: str
    name: str
    start_time: float
    end_time: float | None = None
    input: Any = None
    output: Any = None
    metadata: dict = field(default_factory=dict)
    tags: list[str] = field(default_factory=list)
    user_id: str | None = None
    session_id: str | None = None
    git_commit: str | None = None
    error: str | None = None
    spans: list[Span] = field(default_factory=list)

    def _persist(self) -> None:
        try:
            from pyntrace.db import get_conn
            conn = get_conn()
            with conn:
                conn.execute(
                    """INSERT OR REPLACE INTO traces
                       (id, name, start_time, end_time, input, output,
                        metadata, tags, user_id, session_id, git_commit, error)
                       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                    (self.id, self.name, self.start_time, self.end_time,
                     json.dumps(self.input), json.dumps(self.output),
                     json.dumps(self.metadata), json.dumps(self.tags),
                     self.user_id, self.session_id, self.git_commit, self.error),
                )
            conn.close()
        except Exception:
            pass


@contextmanager
def trace(
    name: str,
    input: Any = None,
    tags: list[str] | None = None,
    user_id: str | None = None,
    session_id: str | None = None,
    metadata: dict | None = None,
) -> Generator[Trace, None, None]:
    """
    Context manager to trace an operation.

    Usage:
        with pyntrace.trace("my_chatbot", input=user_msg) as t:
            response = my_chatbot(user_msg)
            t.output = response
    """
    from pyntrace.git_tracker import get_current_commit

    trace_obj = Trace(
        id=str(uuid.uuid4()),
        name=name,
        start_time=time.time(),
        input=input,
        tags=tags or [],
        user_id=user_id,
        session_id=session_id,
        metadata=metadata or {},
        git_commit=get_current_commit(),
    )

    token = _current_trace_id.set(trace_obj.id)
    try:
        yield trace_obj
    except Exception as e:
        trace_obj.error = str(e)
        raise
    finally:
        trace_obj.end_time = time.time()
        _current_trace_id.reset(token)
        trace_obj._persist()


@contextmanager
def span(
    name: str,
    span_type: str = "custom",
    input: Any = None,
    metadata: dict | None = None,
) -> Generator[Span, None, None]:
    """
    Context manager for a span within a trace.

    Usage:
        with pyntrace.trace("request") as t:
            with pyntrace.span("llm_call", span_type="llm") as s:
                response = call_llm(prompt)
                s.output = response
    """
    trace_id = _current_trace_id.get() or str(uuid.uuid4())
    parent_span_id = _current_span_id.get()

    span_obj = Span(
        id=str(uuid.uuid4()),
        trace_id=trace_id,
        parent_span_id=parent_span_id,
        name=name,
        span_type=span_type,
        start_time=time.time(),
        input=input,
        metadata=metadata or {},
    )

    token = _current_span_id.set(span_obj.id)
    try:
        yield span_obj
    finally:
        span_obj.end_time = time.time()
        span_obj.duration_ms = (span_obj.end_time - span_obj.start_time) * 1000
        _current_span_id.reset(token)
        span_obj._persist()
