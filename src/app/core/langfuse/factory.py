"""Langfuse tracer factory (delegates to tracing domain)."""

from functools import lru_cache

from src.app.core.common.config import settings as default_settings
from src.app.core.tracing.factory import make_langfuse_tracer as _make_langfuse_tracer
from src.app.core.tracing.langfuse_tracer import LangfuseTracer


def get_settings():
    """Return application settings (imported lazily for test overrides)."""
    return default_settings


@lru_cache(maxsize=1)
def make_langfuse_tracer() -> LangfuseTracer:
    """Create a process-wide Langfuse tracer instance."""
    return _make_langfuse_tracer(get_settings())
