"""Tracing middleware for per-request observation lifecycle across tracers."""

from __future__ import annotations

import time
from contextlib import ExitStack
from typing import Any, Callable, Optional

from src.app.core.common.logging import logger
from src.app.core.graph.callback_utils import extend_graph_callbacks
from src.app.core.middleware.types import AgentContext, AgentMiddleware, InvokeResult
from src.app.core.tracing.agent_tracer import AgentTracer
from src.app.core.tracing.callback_handler import LangCallbackHandler
from src.app.core.tracing.session import RequestTracingState


def _default_build_trace_input(ctx: AgentContext) -> dict[str, Any]:
    query = ctx.metadata.get("query")
    if query:
        return {"query": query}
    if ctx.messages:
        return {"query": ctx.messages[-1].content}
    return {}


def _default_build_trace_metadata(ctx: AgentContext) -> dict[str, Any]:
    return dict(ctx.metadata.get("trace_metadata", {}))


def _default_build_trace_output(ctx: AgentContext, result: InvokeResult) -> dict[str, Any]:
    execution_time = time.time() - ctx.metadata.get("_trace_start_time", time.time())
    answer = result[-1].content if result else ""
    return {
        "answer": answer,
        "execution_time": execution_time,
    }


class TracingMiddleware(AgentMiddleware):
    """Creates root observations and wires LangChain callbacks for each configured tracer."""

    def __init__(
        self,
        agent_tracer: AgentTracer,
        trace_name: str,
        *,
        environment: Optional[str] = None,
        build_trace_input: Optional[Callable[[AgentContext], dict]] = None,
        build_trace_metadata: Optional[Callable[[AgentContext], dict]] = None,
        build_trace_output: Optional[Callable[[AgentContext, InvokeResult], dict]] = None,
    ) -> None:
        self._agent_tracer = agent_tracer
        self._trace_name = trace_name
        self._environment = environment
        self._build_trace_input = build_trace_input or _default_build_trace_input
        self._build_trace_metadata = build_trace_metadata or _default_build_trace_metadata
        self._build_trace_output = build_trace_output or _default_build_trace_output

    async def before_invoke(self, ctx: AgentContext) -> Optional[InvokeResult]:
        if not self._agent_tracer.is_enabled:
            return None

        ctx.metadata["_trace_start_time"] = time.time()
        exit_stack = ExitStack()
        ctx.metadata["_tracing_exit_stack"] = exit_stack

        try:
            trace_input = self._build_trace_input(ctx)
            trace_metadata = self._build_trace_metadata(ctx)
            user_id = ctx.metadata.get("user_id", ctx.user_id)
            tags = ctx.metadata.get("trace_tags")

            tracing_state = self._agent_tracer.open_request(
                exit_stack,
                self._trace_name,
                input_data=trace_input,
                user_id=user_id,
                session_id=ctx.session_id,
                metadata=trace_metadata,
                tags=tags,
                environment=self._environment,
            )
            if tracing_state is None:
                exit_stack.close()
                ctx.metadata.pop("_tracing_exit_stack", None)
                return None

            ctx.metadata["trace"] = tracing_state

            handlers = self._agent_tracer.get_callback_handlers()
            if handlers:
                callback_handler = LangCallbackHandler(handlers)
                callbacks = ctx.config.setdefault("callbacks", [])
                if callback_handler not in callbacks:
                    callbacks.append(callback_handler)
                extend_graph_callbacks(ctx, [callback_handler])
        except Exception:
            logger.warning("tracing_middleware_before_invoke_failed", exc_info=True)
            exit_stack.close()
            ctx.metadata.pop("_tracing_exit_stack", None)
            ctx.metadata.pop("trace", None)

        return None

    def _finalize_traces(
        self,
        ctx: AgentContext,
        *,
        output: Optional[dict[str, Any]] = None,
        error: Optional[Exception] = None,
    ) -> None:
        tracing_state = ctx.metadata.get("trace")
        if not isinstance(tracing_state, RequestTracingState):
            return

        trace_id = self._agent_tracer.finalize_request(tracing_state, output=output, error=error)
        if trace_id:
            ctx.metadata["trace_id"] = trace_id

    async def after_invoke(self, ctx: AgentContext, result: InvokeResult) -> InvokeResult:
        try:
            output = self._build_trace_output(ctx, result)
            self._finalize_traces(ctx, output=output)
        except Exception:
            logger.warning("tracing_middleware_after_invoke_failed", exc_info=True)

        exit_stack = ctx.metadata.get("_tracing_exit_stack")
        if exit_stack is not None:
            try:
                exit_stack.close()
            except Exception:
                logger.warning("tracing_middleware_exit_stack_close_failed", exc_info=True)
            ctx.metadata.pop("_tracing_exit_stack", None)

        return result

    async def on_error(self, ctx: AgentContext, error: Exception) -> Optional[InvokeResult]:
        try:
            self._finalize_traces(ctx, error=error)
        except Exception:
            logger.warning("tracing_middleware_on_error_failed", exc_info=True)

        exit_stack = ctx.metadata.get("_tracing_exit_stack")
        if exit_stack is not None:
            try:
                exit_stack.close()
            except Exception:
                logger.warning("tracing_middleware_exit_stack_close_failed", exc_info=True)
            ctx.metadata.pop("_tracing_exit_stack", None)

        return None
