"""FastAPI dependency getters and typed aliases for app.state singletons.

Single-tenant service: no database or user sessions. Auth is a single static API key (SANDTRAP_API_KEY); unset means open (local demo).
"""

import secrets
from typing import Annotated, Optional

from fastapi import Depends, HTTPException, Request
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer

from src.app.core.common.config import Settings
from src.app.agents.open_deep_research.agent_deep_research import DeepResearchAgent
from src.app.core.tracing.agent_tracer import AgentTracer

security = HTTPBearer(auto_error=False)


def get_settings(request: Request) -> Settings:
    return request.app.state.settings


def get_agent_tracer(request: Request) -> AgentTracer:
    return request.app.state.agent_tracer


def get_deep_research_agent(request: Request) -> DeepResearchAgent:
    return request.app.state.deep_research_agent


SettingsDep = Annotated[Settings, Depends(get_settings)]
DeepResearchAgentDep = Annotated[DeepResearchAgent, Depends(get_deep_research_agent)]
AgentTracerDep = Annotated[AgentTracer, Depends(get_agent_tracer)]


async def require_api_key(
    settings: SettingsDep,
    credentials: Optional[HTTPAuthorizationCredentials] = Depends(security),
) -> None:
    expected = settings.SANDTRAP_API_KEY
    if not expected:
        return
    if credentials is None or not secrets.compare_digest(credentials.credentials, expected):
        raise HTTPException(status_code=401, detail="Invalid API key", headers={"WWW-Authenticate": "Bearer"})


ApiKeyDep = Annotated[None, Depends(require_api_key)]
