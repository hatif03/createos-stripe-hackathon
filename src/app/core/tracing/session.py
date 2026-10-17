"""Per-request tracing state shared across tracers."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any


@dataclass
class RequestTracingState:
    """Roots opened by each tracer for one agent invoke."""

    roots: dict[str, Any]

    def root_for(self, tracer_name: str) -> Any:
        return self.roots.get(tracer_name)
