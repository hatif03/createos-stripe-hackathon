"""Unit tests for LangCallbackHandler."""

from unittest.mock import AsyncMock
from uuid import uuid4

import pytest

from src.app.core.tracing.callback_handler import LangCallbackHandler


@pytest.mark.asyncio
async def test_lang_callback_handler_dispatches_to_all_handlers():
    handler_a = AsyncMock()
    handler_b = AsyncMock()
    composite = LangCallbackHandler([handler_a, handler_b])
    run_id = uuid4()

    await composite.on_chain_start({"name": "test"}, {"input": 1}, run_id=run_id)

    handler_a.on_chain_start.assert_awaited_once()
    handler_b.on_chain_start.assert_awaited_once()


@pytest.mark.asyncio
async def test_lang_callback_handler_continues_when_one_handler_fails():
    handler_a = AsyncMock()
    handler_a.on_tool_end.side_effect = RuntimeError("boom")
    handler_b = AsyncMock()
    composite = LangCallbackHandler([handler_a, handler_b])
    run_id = uuid4()

    await composite.on_tool_end("result", run_id=run_id)

    handler_b.on_tool_end.assert_awaited_once()
