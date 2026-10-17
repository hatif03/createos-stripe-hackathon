"""Abstract base tracer for multi-sink observability."""

from __future__ import annotations

from abc import ABC, abstractmethod
from contextlib import contextmanager
from typing import Any, Generator, Optional

from langchain_core.callbacks import AsyncCallbackHandler


class BaseTracer(ABC):
    """Common tracing API implemented by Langfuse, file, and future sinks."""

    name: str = "base"

    @property
    @abstractmethod
    def is_enabled(self) -> bool:
        """Return whether this tracer should participate in a request."""

    @contextmanager
    @abstractmethod
    def trace_agent_request(
        self,
        name: str,
        *,
        input_data: Optional[Any] = None,
        user_id: Optional[Any] = None,
        session_id: Optional[str] = None,
        metadata: Optional[dict[str, Any]] = None,
        tags: Optional[list[str]] = None,
        environment: Optional[str] = None,
    ) -> Generator[Any, None, None]:
        """Open a root request observation for one agent invoke."""

    def get_callback_handler(self) -> Optional[AsyncCallbackHandler]:
        """Return a LangChain callback handler for the active request scope."""
        return None

    def create_span(
        self,
        trace: Any,
        name: str,
        input_data: Optional[Any] = None,
        metadata: Optional[dict[str, Any]] = None,
    ) -> Any:
        return None

    def end_span(
        self,
        span: Any,
        output: Optional[Any] = None,
        metadata: Optional[dict[str, Any]] = None,
    ) -> None:
        return None

    def update_span(
        self,
        span: Any,
        output: Optional[Any] = None,
        metadata: Optional[dict[str, Any]] = None,
        level: Optional[str] = None,
        status_message: Optional[str] = None,
    ) -> None:
        return None

    def get_trace_id(self, trace: Any = None) -> Optional[str]:
        return None

    def submit_feedback(
        self,
        trace_id: str,
        score: float,
        name: str = "user-feedback",
        comment: Optional[str] = None,
    ) -> bool:
        return False

    def flush(self) -> None:
        return None

    def shutdown(self) -> None:
        return None

    def start_generation(
        self,
        name: str,
        model: str,
        input_data: Optional[Any] = None,
        metadata: Optional[dict[str, Any]] = None,
    ) -> Any:
        return None

    def start_span(
        self,
        name: str,
        input_data: Optional[Any] = None,
        metadata: Optional[dict[str, Any]] = None,
    ) -> Any:
        return None
