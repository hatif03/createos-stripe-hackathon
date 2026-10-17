"""In-process scan job manager for the Sandtrap API (threads; one sandbox scan at a time)."""

from __future__ import annotations

import re
import threading
import time
import uuid
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from typing import Callable

from src.app.sandtrap.types import Report

MAX_CONCURRENT_SCANS = 1
MAX_STR = 4000
FIXTURES = Path(__file__).resolve().parents[3] / "fixtures"
_FIXTURE_RE = re.compile(r"^[a-z0-9][a-z0-9_-]{0,40}$")
_PYPI_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,60}(==[A-Za-z0-9.]+)?$")


def resolve_target(target: str) -> str:
    """Allow only `fixture:<name>` (bundled fixtures) or `pypi:<spec>`; never host paths or URLs."""
    if not isinstance(target, str):
        raise ValueError("target must be a string")
    kind, _, rest = target.partition(":")
    if kind == "fixture" and _FIXTURE_RE.fullmatch(rest):
        path = FIXTURES / rest
        if (path / "setup.py").is_file():
            return str(path)
        raise ValueError(f"unknown fixture: {rest}")
    if kind == "pypi" and _PYPI_RE.fullmatch(rest):
        return f"pypi:{rest}"
    raise ValueError("target must be 'fixture:<name>' or 'pypi:<name>[==version]'")


def _trim(data: dict) -> dict:
    return {k: (v[:MAX_STR] if k in ("terminal", "digest") and isinstance(v, str) else v) for k, v in data.items()}


class _Job:
    def __init__(self, target: str):
        self.id = uuid.uuid4().hex[:10]
        self.target = target
        self.state = "queued"
        self.created_at = time.time()
        self.events: list[dict] = []
        self.report: Report | None = None
        self.error = ""


class JobManager:
    def __init__(self, scan_fn: Callable[..., Report] | None = None):
        self._scan_fn = scan_fn
        self._pool = ThreadPoolExecutor(max_workers=2)
        self._sem = threading.Semaphore(MAX_CONCURRENT_SCANS)
        self._lock = threading.Lock()
        self._jobs: dict[str, _Job] = {}

    def submit(self, target: str, probe_budget: int = 5, remediate: bool = True) -> str:
        resolved = resolve_target(target)
        job = _Job(target)
        with self._lock:
            self._jobs[job.id] = job
        self._pool.submit(self._run, job, resolved, probe_budget, remediate)
        return job.id

    def _run(self, job: _Job, resolved: str, probe_budget: int, remediate: bool) -> None:
        def emit(kind: str, data: dict) -> None:
            with self._lock:
                job.events.append({"i": len(job.events), "kind": kind, "data": _trim(data)})

        with self._sem:
            job.state = "running"
            try:
                scan_fn = self._scan_fn
                if scan_fn is None:
                    from src.app.sandtrap.graph import scan as scan_fn  # lazy: heavy imports
                job.report = scan_fn(resolved, emit=emit, probe_budget=probe_budget, remediate=remediate)
                job.state = "done"
            except Exception as exc:
                job.error = f"{type(exc).__name__}: {exc}"[:500]
                job.state = "error"

    def status(self, job_id: str) -> dict | None:
        j = self._jobs.get(job_id)
        if j is None:
            return None
        out = {"job": j.id, "state": j.state, "created_at": j.created_at, "target": j.target, "error": j.error}
        if j.report is not None:
            out |= {"verdict": j.report.verdict, "score": j.report.score}
        return out

    def events(self, job_id: str, start: int = 0) -> list[dict]:
        j = self._jobs.get(job_id)
        with self._lock:
            return list(j.events[start:]) if j else []

    def report(self, job_id: str) -> Report | None:
        j = self._jobs.get(job_id)
        return j.report if j else None

    def recent(self, limit: int = 20) -> list[dict]:
        jobs = sorted(self._jobs.values(), key=lambda j: j.created_at, reverse=True)[:limit]
        return [
            {"job": j.id, "target": j.target, "state": j.state, "verdict": j.report.verdict if j.report else None}
            for j in jobs
        ]
