"""Middleware for adding a request id to the logging context (JWT/session binding dropped with the DB layer)."""

import uuid
from typing import Callable

from fastapi import Request
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.responses import Response

from src.app.core.common.logging import (
    bind_context,
    clear_context,
)


class LoggingContextMiddleware(BaseHTTPMiddleware):
    """Bind a per-request id to structlog context and always clear it afterwards."""

    async def dispatch(self, request: Request, call_next: Callable) -> Response:
        """Bind request_id for the duration of the request."""
        try:
            clear_context()
            bind_context(request_id=request.headers.get("x-request-id") or uuid.uuid4().hex[:12])
            return await call_next(request)
        finally:
            clear_context()
