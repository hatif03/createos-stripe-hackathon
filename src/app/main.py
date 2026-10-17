"""This file contains the main application entry point.

Sandtrap service entry point: API routes, metrics, rate limiting, tracing and the deep-research agent.
"""

from contextlib import asynccontextmanager

import uvicorn
from dotenv import load_dotenv
from fastapi import (
    FastAPI,
    Request,
    status,
)
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.cors import CORSMiddleware
from starlette.responses import JSONResponse

from src.app.agents.open_deep_research.factory import make_deep_research_agent
from src.app.api.logging_context import LoggingContextMiddleware
from src.app.api.metrics.http_metrics import setup_metrics
from src.app.api.metrics.middleware import MetricsMiddleware
from src.app.api.security.limiter import setup_rate_limit
from src.app.api.v1.api import api_router
from src.app.core.common.config import settings
from src.app.core.common.logging import logger
from src.app.core.tracing.factory import make_agent_tracer

load_dotenv()


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Wire the dependency graph onto app.state at startup."""
    app.state.settings = settings
    agent_tracer = make_agent_tracer(settings)
    app.state.agent_tracer = agent_tracer
    app.state.deep_research_agent = await make_deep_research_agent(None, None, agent_tracer=agent_tracer)

    logger.info(
        "application_startup",
        project_name=settings.PROJECT_NAME,
        version=settings.VERSION,
        api_prefix=settings.API_V1_STR,
    )

    yield

    agent_tracer.shutdown()
    logger.info("application_shutdown")


app = FastAPI(
    title=settings.PROJECT_NAME,
    version=settings.VERSION,
    description=settings.DESCRIPTION,
    openapi_url=f"{settings.API_V1_STR}/openapi.json",
    lifespan=lifespan,
)

setup_metrics(app)
setup_rate_limit(app)

app.add_middleware(LoggingContextMiddleware)
app.add_middleware(MetricsMiddleware)


@app.exception_handler(RequestValidationError)
async def validation_exception_handler(request: Request, exc: RequestValidationError):
    """Handle validation errors from request data."""
    formatted_errors = []
    for error in exc.errors():
        loc = " -> ".join([str(loc_part) for loc_part in error["loc"] if loc_part != "body"])
        formatted_errors.append({"field": loc, "message": error["msg"]})

    return JSONResponse(
        status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
        content={"detail": "Validation error", "errors": formatted_errors},
    )


app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.ALLOWED_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(api_router, prefix=settings.API_V1_STR)

if __name__ == "__main__":
    uvicorn.run(app, host="127.0.0.1", port=8000)
