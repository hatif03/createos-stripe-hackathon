"""Middleware that adds structured logging around agent invocations."""

from typing import Any, Optional

from src.app.core.middleware.types import AgentContext, AgentMiddleware, InvokeResult
from src.app.core.common.logging import logger


class LoggingMiddleware(AgentMiddleware):
    """Logs agent lifecycle events: invoke, model calls, and tool calls."""

    async def before_invoke(self, ctx: AgentContext) -> Optional[InvokeResult]:
        logger.info(
            "agent_invoke_started",
            agent_name=ctx.agent_name,
            session_id=ctx.session_id,
            user_id=ctx.user_id,
            message_count=len(ctx.messages),
        )
        return None

    async def after_invoke(self, ctx: AgentContext, result: InvokeResult) -> InvokeResult:
        logger.info(
            "agent_invoke_completed",
            agent_name=ctx.agent_name,
            session_id=ctx.session_id,
            result_count=len(result),
        )
        return result

    async def before_model_call(
        self,
        ctx: AgentContext,
        *,
        messages: list,
        model_name: str,
    ) -> list:
        logger.debug(
            "model_call_started",
            agent_name=ctx.agent_name,
            session_id=ctx.session_id,
            model_name=model_name,
            message_count=len(messages),
        )
        return messages

    async def after_model_call(
        self,
        ctx: AgentContext,
        *,
        response: Any,
        model_name: str,
    ) -> Any:
        logger.debug(
            "model_call_completed",
            agent_name=ctx.agent_name,
            session_id=ctx.session_id,
            model_name=model_name,
        )
        return response

    async def before_tool_call(
        self,
        ctx: AgentContext,
        *,
        tool_name: str,
        tool_args: dict,
    ) -> dict:
        logger.info(
            "tool_call_started",
            agent_name=ctx.agent_name,
            session_id=ctx.session_id,
            tool_name=tool_name,
        )
        return tool_args

    async def after_tool_call(
        self,
        ctx: AgentContext,
        *,
        tool_name: str,
        tool_result: Any,
    ) -> Any:
        logger.info(
            "tool_call_completed",
            agent_name=ctx.agent_name,
            session_id=ctx.session_id,
            tool_name=tool_name,
        )
        return tool_result
