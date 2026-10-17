"""Deep research agent factory (long-term memory is optional; dropped in this build)."""

from typing import Any

from src.app.agents.open_deep_research.agent_deep_research import (
    DeepResearchAgent,
    build_deep_research_trace_metadata,
    build_deep_research_trace_output,
)
from src.app.core.common.config import settings
from src.app.core.guardrails import GuardrailMiddleware
from src.app.core.metrics import LlmMetricsMiddleware
from src.app.core.middleware import ErrorHandlingMiddleware, LoggingMiddleware
from src.app.core.tracing import AgentTracer, TracingMiddleware


async def make_deep_research_agent(
    checkpointer: Any | None = None,
    memory_service: Any | None = None,
    agent_tracer: AgentTracer | None = None,
) -> DeepResearchAgent:
    """Create and compile a deep research agent.

    Args:
        checkpointer: LangGraph checkpointer (Postgres/SQLite), or None.
        memory_service: Optional long-term memory service; None disables the memory middleware.
        agent_tracer: Optional agent tracer for observability.
    """
    tracer = agent_tracer or AgentTracer([])
    middlewares = [
        TracingMiddleware(
            agent_tracer=tracer,
            trace_name="deep_research_request",
            environment=settings.ENVIRONMENT.value,
            build_trace_metadata=build_deep_research_trace_metadata,
            build_trace_output=build_deep_research_trace_output,
        ),
        LoggingMiddleware(),
        GuardrailMiddleware(agent_tracer=tracer),
        LlmMetricsMiddleware(),
        ErrorHandlingMiddleware(),
    ]
    if memory_service is not None:
        from src.app.core.memory import MemoryMiddleware

        middlewares.append(MemoryMiddleware(memory=memory_service))
    agent = DeepResearchAgent(
        "Deep Research",
        checkpointer,
        middlewares=middlewares,
        memory_service=memory_service,
    )
    await agent.compile()
    return agent
