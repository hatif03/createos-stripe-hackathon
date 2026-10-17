"""Backward-compatible alias for unified tracing middleware."""

from src.app.core.tracing.middleware import TracingMiddleware

LangfuseTracingMiddleware = TracingMiddleware

__all__ = ["LangfuseTracingMiddleware", "TracingMiddleware"]
