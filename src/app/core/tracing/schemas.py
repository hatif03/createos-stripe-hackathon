"""Pydantic schemas for graph execution traces."""

from typing import Any, List, Optional

from pydantic import BaseModel, Field


class TraceEventResponse(BaseModel):
    event_type: str
    name: str
    run_id: str
    parent_run_id: Optional[str] = None
    timestamp: float
    duration_ms: Optional[float] = None
    input: Optional[Any] = None
    output: Optional[Any] = None
    error: Optional[str] = None
    tags: List[str] = Field(default_factory=list)
    metadata: dict[str, Any] = Field(default_factory=dict)


class TraceSummaryResponse(BaseModel):
    event_count: int
    nodes: List[str] = Field(default_factory=list)
    tools: List[str] = Field(default_factory=list)
    models: List[str] = Field(default_factory=list)
    errors: List[str] = Field(default_factory=list)


class GraphTraceResponse(BaseModel):
    started_at: float
    finished_at: Optional[float] = None
    duration_ms: Optional[float] = None
    events: List[TraceEventResponse] = Field(default_factory=list)
    summary: TraceSummaryResponse
    steps: List[str] = Field(default_factory=list, description="Human-readable trace steps")
