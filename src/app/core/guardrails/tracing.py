"""Span helpers for guardrail observability."""

from contextlib import contextmanager
from typing import Any, Generator, Optional

from src.app.core.tracing.agent_tracer import AgentTracer
from src.app.core.tracing.session import RequestTracingState


@contextmanager
def guardrail_span(
    name: str,
    *,
    agent_tracer: Optional[AgentTracer] = None,
    trace: Any | None = None,
    input_data: Optional[Any] = None,
    metadata: Optional[dict[str, Any]] = None,
) -> Generator[dict[str, Any], None, None]:
    """Create child spans under the active request trace for a guardrail check.

    Yields a mutable dict; set ``output`` and optional ``metadata`` keys before exit
    to record span results on every enabled tracer.
    """
    span_result: dict[str, Any] = {}
    active_spans: list[tuple[Any, Any]] = []

    if agent_tracer is not None and trace is not None:
        tracing_state: RequestTracingState | None = None
        if isinstance(trace, RequestTracingState):
            tracing_state = trace
        elif hasattr(trace, "roots"):
            tracing_state = RequestTracingState(roots=trace.roots)

        if tracing_state is not None:
            active_spans = agent_tracer.create_spans(
                tracing_state,
                name,
                input_data=input_data,
                metadata=metadata,
            )

    try:
        yield span_result
    finally:
        if agent_tracer is not None:
            agent_tracer.end_spans(
                active_spans,
                output=span_result.get("output"),
                metadata=span_result.get("metadata"),
            )
