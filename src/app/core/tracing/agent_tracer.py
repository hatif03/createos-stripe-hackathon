"""Facade that coordinates all configured tracers for one agent runtime."""

from __future__ import annotations

from contextlib import ExitStack
from typing import Any, Iterable, Optional

from langchain_core.callbacks import AsyncCallbackHandler

from src.app.core.common.logging import logger
from src.app.core.tracing.base import BaseTracer
from src.app.core.tracing.langfuse_tracer import LangfuseTracer
from src.app.core.tracing.session import RequestTracingState


class AgentTracer:
    """Single entry point for multi-sink tracing; owns iteration over tracers."""

    def __init__(self, tracers: Iterable[BaseTracer]) -> None:
        self._tracers = list(tracers)

    @property
    def registered_tracers(self) -> tuple[BaseTracer, ...]:
        """Configured tracers (enabled or not)."""
        return tuple(self._tracers)

    @property
    def is_enabled(self) -> bool:
        return bool(self._enabled_tracers())

    def langfuse_tracer(self) -> LangfuseTracer | None:
        for tracer in self._tracers:
            if isinstance(tracer, LangfuseTracer):
                return tracer
        return None

    def open_request(
        self,
        exit_stack: ExitStack,
        name: str,
        *,
        input_data: Optional[Any] = None,
        user_id: Optional[Any] = None,
        session_id: Optional[str] = None,
        metadata: Optional[dict[str, Any]] = None,
        tags: Optional[list[str]] = None,
        environment: Optional[str] = None,
    ) -> RequestTracingState | None:
        """Enter root trace contexts for every enabled tracer."""
        enabled = self._enabled_tracers()
        if not enabled:
            return None

        roots: dict[str, Any] = {}
        for tracer in enabled:
            root = exit_stack.enter_context(
                tracer.trace_agent_request(
                    name,
                    input_data=input_data,
                    user_id=user_id,
                    session_id=session_id,
                    metadata=metadata,
                    tags=tags,
                    environment=environment,
                )
            )
            roots[tracer.name] = root

        return RequestTracingState(roots=roots)

    def get_callback_handlers(self) -> list[AsyncCallbackHandler]:
        handlers: list[AsyncCallbackHandler] = []
        for tracer in self._enabled_tracers():
            handler = tracer.get_callback_handler()
            if handler is not None:
                handlers.append(handler)
        return handlers

    def finalize_request(
        self,
        tracing_state: RequestTracingState,
        *,
        output: Optional[dict[str, Any]] = None,
        error: Optional[Exception] = None,
    ) -> Optional[str]:
        """Update roots, flush all tracers, and return Langfuse trace id when available."""
        trace_id: Optional[str] = None

        for tracer in self._enabled_tracers():
            root = tracing_state.root_for(tracer.name)
            if root is None:
                continue
            try:
                if error is not None and tracer.name == "langfuse":
                    root.update(output={"error": str(error)}, level="ERROR")
                elif output is not None and hasattr(root, "update"):
                    root.update(output=output)
            except Exception:
                logger.warning(
                    "agent_tracer_root_update_failed",
                    tracer=tracer.name,
                    exc_info=True,
                )

        for tracer in self._enabled_tracers():
            if tracer.name != "langfuse":
                continue
            trace_id = tracer.get_trace_id(tracing_state.root_for(tracer.name))
            break

        for tracer in self._enabled_tracers():
            try:
                tracer.flush()
            except Exception:
                logger.warning("agent_tracer_flush_failed", tracer=tracer.name, exc_info=True)

        return trace_id

    def create_spans(
        self,
        tracing_state: RequestTracingState,
        name: str,
        *,
        input_data: Optional[Any] = None,
        metadata: Optional[dict[str, Any]] = None,
    ) -> list[tuple[BaseTracer, Any]]:
        spans: list[tuple[BaseTracer, Any]] = []
        for tracer in self._enabled_tracers():
            root = tracing_state.root_for(tracer.name)
            if root is None:
                continue
            span = tracer.create_span(root, name, input_data=input_data, metadata=metadata)
            if span is not None:
                spans.append((tracer, span))
        return spans

    def end_spans(
        self,
        spans: list[tuple[BaseTracer, Any]],
        *,
        output: Any = None,
        metadata: Optional[dict[str, Any]] = None,
    ) -> None:
        for tracer, span in spans:
            tracer.end_span(span, output=output, metadata=metadata)

    def shutdown(self) -> None:
        for tracer in self._tracers:
            tracer.shutdown()

    def _enabled_tracers(self) -> list[BaseTracer]:
        return [tracer for tracer in self._tracers if tracer.is_enabled]
