import json
import threading
import time

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from src.app.api.security.limiter import limiter, setup_rate_limit
from src.app.api.v1.sandtrap import router
from src.app.core.common.config import settings
from src.app.sandtrap.jobs import JobManager, resolve_target
from src.app.sandtrap.types import Finding, Report

_lock = threading.Lock()
_running = 0
_max_running = 0


def fake_scan(target, emit=None, out_dir="out", probe_budget=5, remediate=True):
    global _running, _max_running
    with _lock:
        _running += 1
        _max_running = max(_max_running, _running)
    try:
        emit("stage", {"name": "setup"})
        time.sleep(0.2)
        emit("verdict", {"verdict": "malicious", "terminal": "x" * 10000})
        return Report(
            job="abc123def0", target=target, verdict="malicious", score=90,
            findings=[Finding(id="f1", title="<script>evil</script>", severity="high", proof="proof")],
        )
    finally:
        with _lock:
            _running -= 1


def boom(*a, **k):
    raise RuntimeError("sandbox exploded")


@pytest.fixture
def client():
    global _running, _max_running
    _running = _max_running = 0
    limiter.reset()
    app = FastAPI()
    setup_rate_limit(app)
    app.state.settings = settings
    app.state.sandtrap_jobs = JobManager(scan_fn=fake_scan)
    app.include_router(router, prefix="/sandtrap")
    return TestClient(app)


def wait_done(client, job, timeout=5):
    end = time.time() + timeout
    while time.time() < end:
        st = client.get(f"/sandtrap/scan/{job}").json()
        if st["state"] in ("done", "error"):
            return st
        time.sleep(0.05)
    raise AssertionError("job did not finish")


@pytest.mark.parametrize("t", ["fixture:naive-stealer", "pypi:requests", "pypi:requests==2.31.0", "pypi:a_b-c.d"])
def test_resolve_ok(t):
    out = resolve_target(t)
    assert out == t if t.startswith("pypi:") else out.endswith("naive-stealer")


@pytest.mark.parametrize(
    "t",
    ["../etc", "C:\\Windows", "http://x", "fixture:../x", "fixture:nope", "fixture:", "pypi:", "pypi:a b",
     "pypi:-x", "pypi:x==1;rm", "/etc/passwd", "pypi:x/../y", "fixture:Naive"],
)
def test_resolve_rejects(t):
    with pytest.raises(ValueError):
        resolve_target(t)


def test_scan_flow_and_sse(client):
    r = client.post("/sandtrap/scan", json={"target": "fixture:naive-stealer", "probe_budget": 3})
    assert r.status_code == 200
    body = r.json()
    job = body["job"]
    assert body["status_url"] == f"/sandtrap/scan/{job}"
    assert body["events_url"].endswith("/events") and body["report_url"] == f"/sandtrap/report/{job}.html"
    assert client.get(body["status_url"]).json()["state"] in ("queued", "running")

    # SSE connected mid-run: replays from start and ends
    msgs = [json.loads(ln[6:]) for ln in client.get(body["events_url"]).text.split("\n\n") if ln.startswith("data: ")]
    kinds = [m["kind"] for m in msgs]
    assert kinds == ["stage", "verdict", "end"]
    assert len(msgs[1]["data"]["terminal"]) == 4000
    assert msgs[-1]["status"]["state"] == "done"

    st = wait_done(client, job)
    assert st["verdict"] == "malicious" and st["score"] == 90
    # replay after completion
    assert client.get(body["events_url"]).text.count("data: ") == 3

    html = client.get(body["report_url"])
    assert html.status_code == 200 and "text/html" in html.headers["content-type"]
    assert "<script>evil" not in html.text
    js = client.get(f"/sandtrap/report/{job}.json")
    assert js.status_code == 200 and js.json()["verdict"] == "malicious"
    assert client.get("/sandtrap/scan").json()[0]["job"] == job


def test_errors(client):
    assert client.post("/sandtrap/scan", json={"target": "http://x"}).status_code == 422
    assert client.post("/sandtrap/scan", json={"target": "pypi:x", "probe_budget": 99}).status_code == 422
    for path in ("scan/nope", "scan/nope/events", "report/nope.html", "report/nope.json"):
        assert client.get(f"/sandtrap/{path}").status_code == 404


def test_failed_job(client):
    client.app.state.sandtrap_jobs = JobManager(scan_fn=boom)
    job = client.post("/sandtrap/scan", json={"target": "pypi:x"}).json()["job"]
    st = wait_done(client, job)
    assert st["state"] == "error" and "sandbox exploded" in st["error"]
    assert client.get(f"/sandtrap/report/{job}.json").status_code == 409


def test_semaphore_serialises():
    jm = JobManager(scan_fn=fake_scan)
    ids = [jm.submit("pypi:a"), jm.submit("pypi:b")]
    time.sleep(0.1)
    assert sorted(jm.status(i)["state"] for i in ids) == ["queued", "running"]
    end = time.time() + 5
    while time.time() < end and not all(jm.status(i)["state"] == "done" for i in ids):
        time.sleep(0.05)
    assert all(jm.status(i)["state"] == "done" for i in ids)
    assert _max_running == 1


def test_real_app_registers_routes():
    from src.app.main import app

    paths = app.openapi()["paths"]
    for p in ("/scan", "/scan/{job}", "/scan/{job}/events", "/report/{job}.html", "/report/{job}.json"):
        assert any(k.endswith("/sandtrap" + p) for k in paths), p
