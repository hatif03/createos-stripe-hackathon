"""API v1 router configuration.

API v1 router: health, the deep-research route, and the Sandtrap routes (scan, report, SSE events) from sandtrap.py.
"""

from datetime import datetime

from fastapi import APIRouter, Request

from src.app.api.security.limiter import limiter
from src.app.api.v1.deep_research import router as deep_research_router
from src.app.api.v1.sandtrap import router as sandtrap_router
from src.app.core.common.config import settings
from src.app.core.common.logging import logger
from src.app.dependencies import SettingsDep

api_router = APIRouter()
api_router.include_router(deep_research_router, prefix="/deep-research", tags=["deep-research"])
api_router.include_router(sandtrap_router, prefix="/sandtrap", tags=["sandtrap"])


@api_router.get("/health")
@limiter.limit(settings.RATE_LIMIT_ENDPOINTS["health"][0])
async def health_check(request: Request, settings: SettingsDep):
    """Liveness check."""
    logger.info("health_check_called")
    return {
        "status": "healthy",
        "version": settings.VERSION,
        "environment": settings.ENVIRONMENT.value,
        "timestamp": datetime.now().isoformat(),
    }


@api_router.get("/")
@limiter.limit(settings.RATE_LIMIT_ENDPOINTS["root"][0])
async def root(request: Request, settings: SettingsDep):
    """Root endpoint returning basic API information."""
    return {
        "name": settings.PROJECT_NAME,
        "version": settings.VERSION,
        "status": "healthy",
        "swagger_url": "/docs",
    }
