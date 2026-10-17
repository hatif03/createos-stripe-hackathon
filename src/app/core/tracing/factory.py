"""Tracing tracer factories."""

from src.app.core.common.config import Settings
from src.app.core.common.logging import logger
from src.app.core.tracing.agent_tracer import AgentTracer
from src.app.core.tracing.base import BaseTracer
from src.app.core.tracing.file_tracer import FileTracer
from src.app.core.tracing.langfuse_tracer import LangfuseTracer


def make_langfuse_tracer(app_settings: Settings | None = None) -> LangfuseTracer:
    """Create a Langfuse tracer instance."""
    from src.app.core.common.config import settings as default_settings

    settings = app_settings or default_settings
    tracer = LangfuseTracer(settings)

    if tracer.client is None:
        return tracer

    try:
        if tracer.client.auth_check():
            logger.info("langfuse_auth_success")
        else:
            logger.error("langfuse_auth_failure")
    except Exception:
        logger.warning("langfuse_auth_check_failed", exc_info=True)

    return tracer


def make_langfuse_tracer_fresh(app_settings: Settings | None = None) -> LangfuseTracer:
    """Alias for tests that need an isolated Langfuse tracer."""
    return make_langfuse_tracer(app_settings)


def make_file_tracer(app_settings: Settings | None = None) -> FileTracer:
    """Create a file tracer instance."""
    from src.app.core.common.config import settings as default_settings

    settings = app_settings or default_settings
    return FileTracer(settings)


def make_file_tracer_fresh(app_settings: Settings | None = None) -> FileTracer:
    """Alias for tests that need an isolated file tracer."""
    return make_file_tracer(app_settings)


def _build_tracers(settings: Settings) -> list[BaseTracer]:
    tracers: list[BaseTracer] = []

    langfuse_tracer = make_langfuse_tracer(settings)
    if langfuse_tracer.is_enabled:
        tracers.append(langfuse_tracer)

    if settings.FILE_TRACING_ENABLED:
        tracers.append(make_file_tracer(settings))

    return tracers


def make_agent_tracer(app_settings: Settings | None = None) -> AgentTracer:
    """Build the configured agent tracer for application wiring."""
    from src.app.core.common.config import settings as default_settings

    settings = app_settings or default_settings
    return AgentTracer(_build_tracers(settings))


def make_agent_tracer_fresh(app_settings: Settings | None = None) -> AgentTracer:
    """Alias for tests that need an isolated agent tracer."""
    return make_agent_tracer(app_settings)


def make_tracers(app_settings: Settings | None = None) -> AgentTracer:
    """Backward-compatible alias for :func:`make_agent_tracer`."""
    return make_agent_tracer(app_settings)
