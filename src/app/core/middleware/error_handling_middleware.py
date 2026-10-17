"""Middleware that provides consistent error handling across agents."""

from typing import Optional

from src.app.core.middleware.types import AgentContext, AgentMiddleware, InvokeResult
from src.app.core.common.config import Environment, settings
from src.app.core.common.logging import logger
from src.app.core.llm.llm_utils import record_llm_error


class ErrorHandlingMiddleware(AgentMiddleware):
    """Catches exceptions, records metrics, re-raises in dev or returns fallback."""

    async def on_error(self, ctx: AgentContext, error: Exception) -> Optional[InvokeResult]:
        model_name = ctx.metadata.get("model_name", "unknown")
        record_llm_error(model_name, ctx.agent_name)

        if settings.ENVIRONMENT == Environment.DEVELOPMENT:
            return None

        logger.exception(
            "agent_invoke_failed",
            agent_name=ctx.agent_name,
            session_id=ctx.session_id,
            error=str(error),
        )
        return []
