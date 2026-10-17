"""Sandtrap HTTP API: submit scans, stream progress (SSE), fetch reports."""

import asyncio
import json

from fastapi import APIRouter, HTTPException, Request
from fastapi.responses import HTMLResponse, JSONResponse, StreamingResponse
from pydantic import BaseModel, Field

from src.app.api.security.limiter import limiter
from src.app.core.common.config import settings
from src.app.dependencies import ApiKeyDep
from src.app.sandtrap.jobs import JobManager
from src.app.sandtrap.report import render_html, render_json

router = APIRouter()


class ScanRequest(BaseModel):
    target: str
    probe_budget: int = Field(5, ge=1, le=8)
    remediate: bool = True


def _jobs(request: Request) -> JobManager:
    state = request.app.state
    if getattr(state, "sandtrap_jobs", None) is None:
        state.sandtrap_jobs = JobManager()
    return state.sandtrap_jobs


def _status_or_404(request: Request, job: str) -> dict:
    status = _jobs(request).status(job)
    if status is None:
        raise HTTPException(status_code=404, detail="unknown job")
    return status


def _done_report(request: Request, job: str):
    status = _status_or_404(request, job)
    report = _jobs(request).report(job)
    if report is None:
        raise HTTPException(status_code=409, detail=f"report not available (state: {status['state']})")
    return report


@router.post("/scan")
@limiter.limit(settings.RATE_LIMIT_ENDPOINTS["scan"][0])
async def start_scan(request: Request, body: ScanRequest, _auth: ApiKeyDep):
    try:
        job = _jobs(request).submit(body.target, body.probe_budget, body.remediate)
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc))
    base = request.url.path.rstrip("/")  # .../scan
    root = base[: -len("/scan")]
    return {
        "job": job,
        "status_url": f"{base}/{job}",
        "events_url": f"{base}/{job}/events",
        "report_url": f"{root}/report/{job}.html",
    }


@router.get("/scan")
@limiter.limit(settings.RATE_LIMIT_ENDPOINTS["report"][0])
async def list_scans(request: Request, _auth: ApiKeyDep):
    return _jobs(request).recent()


@router.get("/scan/{job}")
@limiter.limit(settings.RATE_LIMIT_ENDPOINTS["report"][0])
async def scan_status(request: Request, job: str, _auth: ApiKeyDep):
    return _status_or_404(request, job)


@router.get("/scan/{job}/events")
@limiter.limit(settings.RATE_LIMIT_ENDPOINTS["scan_stream"][0])
async def scan_events(request: Request, job: str, _auth: ApiKeyDep):
    jobs = _jobs(request)
    _status_or_404(request, job)

    async def stream():
        i = 0
        while True:
            state = jobs.status(job)["state"]  # read state BEFORE events so none are missed
            for ev in jobs.events(job, i):
                i = ev["i"] + 1
                yield f"data: {json.dumps(ev, default=str)}\n\n"
            if state in ("done", "error"):
                yield f"data: {json.dumps({'kind': 'end', 'status': jobs.status(job)}, default=str)}\n\n"
                return
            await asyncio.sleep(0.3)

    return StreamingResponse(stream(), media_type="text/event-stream")


@router.get("/report/{job}.html", response_class=HTMLResponse)
@limiter.limit(settings.RATE_LIMIT_ENDPOINTS["report"][0])
async def report_html(request: Request, job: str, _auth: ApiKeyDep):
    return HTMLResponse(render_html(_done_report(request, job)))


@router.get("/report/{job}.json")
@limiter.limit(settings.RATE_LIMIT_ENDPOINTS["report"][0])
async def report_json(request: Request, job: str, _auth: ApiKeyDep):
    return JSONResponse(json.loads(render_json(_done_report(request, job))))
