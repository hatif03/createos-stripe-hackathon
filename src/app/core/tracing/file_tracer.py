"""File-based tracer that persists request traces under logs/tracing."""

from __future__ import annotations

import json
import time
import uuid
from contextlib import contextmanager
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Generator, Optional

from langchain_core.callbacks import AsyncCallbackHandler

from src.app.core.common.config import Settings
from src.app.core.common.logging import logger
from src.app.core.tracing.base import BaseTracer
from src.app.core.tracing.graph_trace import GraphTraceCallback


@dataclass
class FileSpan:
    """In-memory span record for file traces."""

    name: str
    input_data: Any = None
    output_data: Any = None
    metadata: dict[str, Any] = field(default_factory=dict)
    level: Optional[str] = None
    started_at: float = field(default_factory=time.time)
    ended_at: Optional[float] = None


@dataclass
class FileTraceRoot:
    """Root trace handle for one file-backed request."""

    trace_id: str
    name: str
    input_data: Any = None
    output_data: Any = None
    metadata: dict[str, Any] = field(default_factory=dict)
    level: Optional[str] = None
    user_id: Any = None
    session_id: Optional[str] = None
    tags: list[str] = field(default_factory=list)
    environment: Optional[str] = None
    spans: list[FileSpan] = field(default_factory=list)
    graph_trace_callback: Optional[GraphTraceCallback] = None
    started_at: float = field(default_factory=time.time)
    finished_at: Optional[float] = None

    def update(
        self,
        output: Any = None,
        level: Optional[str] = None,
        metadata: Optional[dict[str, Any]] = None,
        **_: Any,
    ) -> None:
        if output is not None:
            self.output_data = output
        if level is not None:
            self.level = level
        if metadata:
            self.metadata.update(metadata)

    def to_dict(self) -> dict[str, Any]:
        graph_trace = None
        if self.graph_trace_callback is not None:
            graph_trace = self.graph_trace_callback.finalize().to_dict()

        return {
            "trace_id": self.trace_id,
            "name": self.name,
            "started_at": self.started_at,
            "finished_at": self.finished_at,
            "input": self.input_data,
            "output": self.output_data,
            "level": self.level,
            "user_id": self.user_id,
            "session_id": self.session_id,
            "tags": self.tags,
            "environment": self.environment,
            "metadata": self.metadata,
            "spans": [
                {
                    "name": span.name,
                    "started_at": span.started_at,
                    "ended_at": span.ended_at,
                    "input": span.input_data,
                    "output": span.output_data,
                    "metadata": span.metadata,
                    "level": span.level,
                }
                for span in self.spans
            ],
            "graph_trace": graph_trace,
        }


class FileTracer(BaseTracer):
    """Persists structured traces as JSON files."""

    name = "file"

    def __init__(self, settings: Settings, *, max_content_length: int = 500) -> None:
        self._settings = settings
        self._max_content_length = max_content_length
        self._output_dir = Path(settings.FILE_TRACING_DIR)
        self._current_root: Optional[FileTraceRoot] = None

    @property
    def is_enabled(self) -> bool:
        return bool(self._settings.FILE_TRACING_ENABLED)

    @contextmanager
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
        if not self.is_enabled:
            yield None
            return

        trace_id = str(uuid.uuid4())
        callback = GraphTraceCallback(max_content_length=self._max_content_length)
        root = FileTraceRoot(
            trace_id=trace_id,
            name=name,
            input_data=input_data,
            metadata=dict(metadata or {}),
            user_id=user_id,
            session_id=session_id,
            tags=list(tags or []),
            environment=environment,
            graph_trace_callback=callback,
        )
        self._current_root = root
        try:
            yield root
        finally:
            root.finished_at = time.time()

    def get_callback_handler(self) -> Optional[AsyncCallbackHandler]:
        if not self.is_enabled or self._current_root is None:
            return None
        return self._current_root.graph_trace_callback

    def create_span(
        self,
        trace: Any,
        name: str,
        input_data: Optional[Any] = None,
        metadata: Optional[dict[str, Any]] = None,
    ) -> Any:
        if not isinstance(trace, FileTraceRoot):
            return None

        span = FileSpan(name=name, input_data=input_data, metadata=dict(metadata or {}))
        trace.spans.append(span)
        return span

    def end_span(
        self,
        span: Any,
        output: Optional[Any] = None,
        metadata: Optional[dict[str, Any]] = None,
    ) -> None:
        if not isinstance(span, FileSpan):
            return

        span.output_data = output
        if metadata:
            span.metadata.update(metadata)
        span.ended_at = time.time()

    def update_span(
        self,
        span: Any,
        output: Optional[Any] = None,
        metadata: Optional[dict[str, Any]] = None,
        level: Optional[str] = None,
        status_message: Optional[str] = None,
    ) -> None:
        if not isinstance(span, FileSpan):
            return

        if output is not None:
            span.output_data = output
        if metadata:
            span.metadata.update(metadata)
        if level is not None:
            span.level = level
        if status_message is not None:
            span.metadata["status_message"] = status_message

    def get_trace_id(self, trace: Any = None) -> Optional[str]:
        if isinstance(trace, FileTraceRoot):
            return trace.trace_id
        if self._current_root is not None:
            return self._current_root.trace_id
        return None

    def flush(self) -> None:
        root = self._current_root
        if root is None or not self.is_enabled:
            return

        try:
            self._output_dir.mkdir(parents=True, exist_ok=True)
            path = self._output_dir / f"{root.trace_id}.json"
            payload = root.to_dict()
            path.write_text(json.dumps(payload, default=str, indent=2), encoding="utf-8")
            logger.info("file_tracer_trace_written", path=str(path), trace_id=root.trace_id)
        except Exception:
            logger.warning("file_tracer_flush_failed", exc_info=True)
        finally:
            self._current_root = None

    def shutdown(self) -> None:
        self.flush()
