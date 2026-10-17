"""Unit tests for TracingMiddleware."""

from contextlib import contextmanager
from unittest.mock import MagicMock

import pytest

from src.app.core.common.model.message import Message
from src.app.core.middleware.pipeline import AgentPipeline
from src.app.core.middleware.types import AgentContext, build_invoke_config
from src.app.core.tracing.agent_tracer import AgentTracer
from src.app.core.tracing.middleware import TracingMiddleware


class _MockTracer:
    name = "langfuse"

    def __init__(self) -> None:
        self.client = MagicMock()
        self.is_enabled = True
        self.flush = MagicMock()
        self._trace_id = "trace-123"

    @contextmanager
    def trace_agent_request(self, name, **kwargs):
        observation = MagicMock()
        observation.trace_id = self._trace_id
        yield observation

    def get_callback_handler(self):
        return MagicMock(name="callback_handler")

    def get_trace_id(self, trace=None):
        if trace is not None:
            return getattr(trace, "trace_id", self._trace_id)
        return self._trace_id


@pytest.mark.asyncio
async def test_tracing_middleware_sets_trace_id_and_callbacks():
    tracer = _MockTracer()
    middleware = TracingMiddleware(
        agent_tracer=AgentTracer([tracer]),
        trace_name="test_agent_request",
        environment="test",
    )

    async def core_invoke(ctx: AgentContext):
        ctx.metadata["graph_result"] = {"messages": []}
        return [Message(role="assistant", content="hello")]

    pipeline = AgentPipeline(middlewares=[middleware], invoke_fn=core_invoke)
    ctx = AgentContext(
        messages=[Message(role="user", content="hi")],
        session_id="session-1",
        user_id=42,
        config=build_invoke_config("session-1", 42, "test-agent"),
        agent_name="test-agent",
        metadata={
            "query": "hi",
            "user_id": 42,
            "trace_metadata": {"service": "test"},
        },
    )

    result = await pipeline.run(ctx)

    assert result[0].content == "hello"
    assert ctx.metadata["trace_id"] == "trace-123"
    assert len(ctx.config["callbacks"]) == 1
    tracer.flush.assert_called_once()


@pytest.mark.asyncio
async def test_tracing_middleware_noop_when_no_enabled_tracers():
    middleware = TracingMiddleware(agent_tracer=AgentTracer([]), trace_name="test_agent_request")

    async def core_invoke(_ctx: AgentContext):
        return [Message(role="assistant", content="ok")]

    pipeline = AgentPipeline(middlewares=[middleware], invoke_fn=core_invoke)
    ctx = AgentContext(
        messages=[Message(role="user", content="hi")],
        session_id="session-1",
        user_id=None,
        config=build_invoke_config("session-1", None, "test-agent"),
        agent_name="test-agent",
        metadata={"query": "hi"},
    )

    result = await pipeline.run(ctx)

    assert result[0].content == "ok"
    assert "trace_id" not in ctx.metadata


@pytest.mark.asyncio
async def test_tracing_middleware_records_error_on_failure():
    tracer = _MockTracer()
    middleware = TracingMiddleware(
        agent_tracer=AgentTracer([tracer]),
        trace_name="test_agent_request",
    )

    async def core_invoke(_ctx: AgentContext):
        raise RuntimeError("boom")

    pipeline = AgentPipeline(middlewares=[middleware], invoke_fn=core_invoke)
    ctx = AgentContext(
        messages=[Message(role="user", content="hi")],
        session_id="session-1",
        user_id=None,
        config=build_invoke_config("session-1", None, "test-agent"),
        agent_name="test-agent",
        metadata={"query": "hi"},
    )

    with pytest.raises(RuntimeError, match="boom"):
        await pipeline.run(ctx)

    tracing_state = ctx.metadata.get("trace")
    assert tracing_state is not None
    root = tracing_state.roots["langfuse"]
    root.update.assert_called()
    assert ctx.metadata.get("trace_id") == "trace-123"
    tracer.flush.assert_called()


@pytest.mark.asyncio
async def test_tracing_middleware_uses_single_composite_callback_for_multiple_tracers():
    tracer_a = _MockTracer()
    tracer_b = _MockTracer()
    tracer_b.name = "file"
    handler_a = MagicMock(name="handler_a")
    handler_b = MagicMock(name="handler_b")
    tracer_a.get_callback_handler = MagicMock(return_value=handler_a)
    tracer_b.get_callback_handler = MagicMock(return_value=handler_b)

    middleware = TracingMiddleware(
        agent_tracer=AgentTracer([tracer_a, tracer_b]),
        trace_name="test_agent_request",
    )

    async def core_invoke(_ctx: AgentContext):
        return [Message(role="assistant", content="ok")]

    pipeline = AgentPipeline(middlewares=[middleware], invoke_fn=core_invoke)
    ctx = AgentContext(
        messages=[Message(role="user", content="hi")],
        session_id="session-1",
        user_id=None,
        config=build_invoke_config("session-1", None, "test-agent"),
        agent_name="test-agent",
        metadata={"query": "hi"},
    )

    await pipeline.run(ctx)

    assert len(ctx.config["callbacks"]) == 1
    composite = ctx.config["callbacks"][0]
    assert composite.__class__.__name__ == "LangCallbackHandler"
