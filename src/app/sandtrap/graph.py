"""Sandtrap scan pipeline as a LangGraph state graph (hackathon-built).

setup (sandbox, canaries, traced install, egress lock) -> baseline -> analyst loop -> finalize (score, report, destroy).
Heavy, non-serialisable objects (the sandbox) live in ``RUNS[job]``; the graph state only carries plain data.
"""

from __future__ import annotations

import hashlib
import os
import re
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable, TypedDict

from langgraph.checkpoint.memory import MemorySaver
from langgraph.graph import END, START, StateGraph

from src.app.core.common.config import settings
from src.app.core.common.logging import logger
from src.app.core.tracing.factory import make_langfuse_tracer
from src.app.sandtrap.analyst import AnalystContext, run_analyst
from src.app.sandtrap.lab import Lab, binary_driver, default_driver, local_modules, npm_driver, script_driver
from src.app.static.capa import run_capa
from src.app.static.virustotal import lookup as virustotal_lookup
from src.app.sandtrap.learn import learn_skill
from src.app.sandtrap.memory import get_memory
from src.app.sandtrap.remediate import run_remediation
from src.app.sandtrap.report import render_terminal, write_report
from src.app.sandtrap.sandbox import REGISTRY_EGRESS, SandboxSession
from src.app.sandtrap.score import score
from src.app.sandtrap.types import AttemptLog, Probe, ProbeResult, Report, StaticFinding

Emit = Callable[[str, dict], None]
SITE_PACKAGES = "/root/work/venv/lib/python3.13/site-packages"
LIMITATIONS = [
    "Dynamic analysis runs on Linux only; Windows executables are not executed.",
    "HTTPS request bodies cannot be read without interception: TLS destinations are recorded by SNI only.",
    "Evasive code that detects tracing or waits longer than the probe timeout may look quiet; such runs are reported as inconclusive, never clean.",
    "Canary proof covers the credential types we plant (ssh key, aws, npm, .env).",
]


class ScanState(TypedDict, total=False):
    job: str
    target: str
    stage: str
    error: str
    report_paths: dict


@dataclass
class RunCtx:
    job: str
    target: str
    emit: Emit
    out_dir: str = "out"
    probe_budget: int = 5
    session: SandboxSession | None = None
    lab: Lab | None = None
    modules: list[str] = field(default_factory=list)
    analyst: AnalystContext | None = None
    install_round: ProbeResult | None = None
    sha256: str = ""
    report: Report | None = None
    patch_diff: str = ""
    remediation: str = ""
    remediate: bool = True
    use_memory: bool = True
    enrich: bool = False
    learned: list[str] = field(default_factory=list)
    binary: bool = False
    npm: bool = False
    script: str = ""
    static: list[StaticFinding] = field(default_factory=list)


RUNS: dict[str, RunCtx] = {}
_TRACER = None


def _langfuse():
    """Process-wide Langfuse tracer (disabled automatically when no keys are configured)."""
    global _TRACER
    if _TRACER is None:
        _TRACER = make_langfuse_tracer(settings)
    return _TRACER


def _dir_hash(path: Path) -> str:
    digest = hashlib.sha256()
    for file in sorted(p for p in path.rglob("*") if p.is_file() and "__pycache__" not in p.parts):
        digest.update(str(file.relative_to(path)).encode())
        digest.update(file.read_bytes())
    return digest.hexdigest()


def node_setup(state: ScanState) -> ScanState:
    ctx = RUNS[state["job"]]
    ctx.emit("stage", {"name": "setup", "detail": "creating sandbox with registry-only egress"})
    ctx.session = SandboxSession(label=ctx.job[:6], egress=REGISTRY_EGRESS).create()
    ctx.lab = Lab(ctx.session)
    ctx.lab.prepare()
    target = ctx.target
    if target.startswith("c:"):
        path = Path(target[2:])
        ctx.binary = True
        ctx.sha256 = hashlib.sha256(path.read_bytes()).hexdigest()
        ctx.emit("stage", {"name": "compile", "detail": f"gcc {path.name} inside the sandbox"})
        install = ctx.lab.install_c(path)
        if install.ok:
            ctx.emit("stage", {"name": "static", "detail": "capa capability + ATT&CK analysis of the binary inside the sandbox"})
            ctx.static = run_capa(ctx.session, "/root/work/bin/sample") + virustotal_lookup(
                ctx.session.run("sha256sum /root/work/bin/sample | cut -d' ' -f1").stdout.strip())
            ctx.emit("static", {"findings": len(ctx.static)})
    elif target.startswith("script:"):
        path = Path(target[7:])
        ctx.script = path.name
        ctx.sha256 = hashlib.sha256(path.read_bytes()).hexdigest()
        ctx.emit("stage", {"name": "upload", "detail": f"{path.name} uploaded (it only runs inside probes, with CI-like fake credentials)"})
        install = ctx.lab.install_script(path)
    elif target.startswith("npm:"):
        path = Path(target[4:])
        ctx.npm = True
        ctx.sha256 = _dir_hash(path)
        ctx.emit("stage", {"name": "install", "detail": f"npm install --ignore-scripts {path.name} (lifecycle scripts run later, under the lure)"})
        install = ctx.lab.install_npm(path)
    elif target.startswith("pypi:"):
        spec = target[5:]
        ctx.emit("stage", {"name": "install", "detail": f"pip install {spec} under strace"})
        install = ctx.lab.install_pypi(spec)
        ctx.modules = [re.split(r"[=<>!\[]", spec)[0].replace("-", "_")]
    else:
        path = Path(target)
        ctx.sha256 = _dir_hash(path)
        ctx.modules = local_modules(path)
        ctx.emit("stage", {"name": "install", "detail": f"pip install {path.name} under strace (registry-only egress)"})
        install = ctx.lab.install_local(path)
    ctx.install_round = ProbeResult(
        probe=Probe(round=-1, label="install"), exit_code=install.exit_code, stdout=install.stdout,
        stderr=install.stderr, events=install.events, sandbox_id=ctx.session.id,
        error="" if install.ok else f"install failed (exit {install.exit_code})",
    )
    ctx.emit("install", {"ok": install.ok, "events": len(install.events)})
    rules = ctx.session.lock_down(phase="analysis", note="registry access closed; lure runs on loopback only")
    ctx.emit("egress", {"rules": rules})
    return {"stage": "setup-done", "error": "" if install.ok else "install-failed"}


def node_baseline(state: ScanState) -> ScanState:
    ctx = RUNS[state["job"]]
    ctx.emit("stage", {"name": "baseline", "detail": "traced run, fake DNS answers NXDOMAIN"})
    driver = (binary_driver() if ctx.binary else npm_driver() if ctx.npm else script_driver(ctx.script) if ctx.script
              else default_driver(ctx.modules))
    probe = Probe(round=0, label="baseline", driver_code=driver)
    result = ctx.lab.run_probe(probe)
    ctx.analyst = AnalystContext(
        lab=ctx.lab, modules=ctx.modules,
        source_roots=["/root/work/src"] if ctx.binary else ["/root/work/pkg", SITE_PACKAGES],
        probe_budget=ctx.probe_budget, emit=ctx.emit,
    )
    ctx.analyst.rounds.append(result)
    if ctx.script:
        ctx.analyst.default_driver_code = driver
        ctx.analyst.source_roots = ["/root/work/src"]
        ctx.analyst.task_note = (
            f"TARGET IS A SHELL SCRIPT ({ctx.script}) in /root/work/src, run the way a CI job or installer would run it. The "
            "environment already holds CI-style fake credentials (AWS_SECRET_ACCESS_KEY, GITHUB_TOKEN, NPM_TOKEN). For run_probe, "
            "driver_code must be a bash script starting with #!/bin/bash (for example set variables, then bash the script)."
        )
    if ctx.npm:
        ctx.analyst.default_driver_code = driver
        ctx.analyst.source_roots = ["/root/work/pkg"]
        ctx.analyst.task_note = (
            "TARGET IS AN NPM PACKAGE installed with --ignore-scripts in /root/work/pkg (read package.json for lifecycle scripts). "
            "The baseline ran its preinstall/install/postinstall scripts the way `npm install` would. For run_probe, driver_code must "
            "be a bash script starting with #!/bin/bash (for example cd /root/work/pkg && node beacon.js, with env vars set inside)."
        )
    if ctx.binary:
        ctx.analyst.default_driver_code = driver
        caps = "; ".join(f.title.replace("capability: ", "") for f in ctx.static[:14]) or "none"
        ctx.analyst.task_note = (
            "TARGET IS A COMPILED ELF (built from the C source under /root/work/src, binary /root/work/bin/sample). There is no "
            "Python package. For run_probe, driver_code must be a bash script starting with #!/bin/bash that runs "
            "/root/work/bin/sample (set env vars inside the script or via env). capa static capabilities found: " + caps
        )
    if ctx.use_memory and not ctx.binary and not ctx.npm and not ctx.script:
        src = ctx.lab.session.run(f"head -c 3500 /root/work/pkg/{ctx.modules[0]}/__init__.py 2>/dev/null").stdout if ctx.modules else ""
        skills = get_memory().relevant_skills(f"{src}\n{ctx.modules}", limit=2)
        if skills:
            ctx.analyst.skills_text = get_memory().render_skills_for_prompt(skills)
            ctx.analyst.used_skills = [s.name for s in skills]
            ctx.emit("skills", {"names": ctx.analyst.used_skills})
    ctx.analyst.attempts.append(AttemptLog(round=0, label="baseline", exit_code=result.exit_code, note="default import driver"))
    ctx.emit("baseline", {"events": len(result.events), "exit": result.exit_code})
    return {"stage": "baseline-done"}


def node_analyst(state: ScanState) -> ScanState:
    ctx = RUNS[state["job"]]
    ctx.emit("stage", {"name": "analyst", "detail": "agent reads the baseline and designs experiments"})
    run_analyst(ctx.analyst)
    a = ctx.analyst
    if not any(r.probe.lure and not r.error for r in a.rounds[1:]):
        # a verdict without a lure experiment is a guess (the model sometimes reads files until it runs out of turns): run one ourselves
        ctx.emit("stage", {"name": "auto-lure", "detail": "the agent ran no lure experiment, so one is run with the default driver"})
        probe = Probe(round=len(a.rounds), label="auto-lure", lure=True, env={"CI": "true"},
                      driver_code=a.default_driver_code or default_driver(ctx.modules))
        a.rounds.append(ctx.lab.run_probe(probe))
    return {"stage": "analysis-done"}


def node_learn(state: ScanState) -> ScanState:
    ctx = RUNS[state["job"]]
    if ctx.use_memory and ctx.analyst:
        try:
            name = learn_skill(ctx.analyst, get_memory(), ctx.emit)
            if name:
                ctx.learned.append(name)
        except Exception as exc:  # learning is a bonus: never lose the verdict
            logger.warning("learn_skill_failed", error=str(exc)[:200], exc_info=True)
    return {"stage": "learned"}


def node_remediate(state: ScanState) -> ScanState:
    ctx = RUNS[state["job"]]
    if ctx.remediate and not ctx.target.startswith("pypi:") and not ctx.binary and not ctx.npm and not ctx.script:
        try:
            ctx.patch_diff, ctx.remediation = run_remediation(ctx)
        except Exception as exc:  # remediation is a bonus step: never lose the verdict
            logger.warning("remediation_failed", error=str(exc)[:200], exc_info=True)
            ctx.remediation = f"Remediation step failed: {type(exc).__name__}"
    return {"stage": "remediated"}


def node_finalize(state: ScanState) -> ScanState:
    ctx = RUNS[state["job"]]
    a = ctx.analyst
    rounds = ([ctx.install_round] if ctx.install_round else []) + (a.rounds if a else [])
    scored = score(rounds, static_findings=ctx.static)
    ctx.session.destroy()
    report = Report(
        job=ctx.job, target=ctx.target, target_kind="pypi" if ctx.target.startswith("pypi:") else "package",
        sha256=ctx.sha256, created_at=datetime.now(timezone.utc).isoformat(timespec="seconds"),
        verdict=scored.verdict, score=scored.score, confidence=scored.confidence, findings=scored.findings,
        rounds=rounds, baseline_only=scored.baseline_only, lure_only=scored.lure_only,
        hypotheses=list(dict.fromkeys(h for h in a.hypotheses if h)) if a else [], summary=a.summary if a else "", attempts=a.attempts if a else [],
        egress_timeline=ctx.session.egress_timeline, model=settings.LLM_MODEL, llm_calls=a.llm_calls if a else 0,
        sandbox_ids=[ctx.session.id, *ctx.session.related_ids], destroyed=ctx.session.destroyed, limitations=LIMITATIONS,
        patch_diff=ctx.patch_diff, remediation=ctx.remediation, used_skills=a.used_skills if a else [],
        learned_skills=ctx.learned, static_findings=ctx.static,
    )
    if ctx.use_memory:
        memory = get_memory()
        report.intel = memory.annotate(report)  # indicators seen in OTHER earlier scans
        memory.remember_scan(report)
        memory.remember_iocs(report)
        if a and a.used_skills:
            proven = report.verdict == "malicious" and report.confidence == "high"
            for skill_name in a.used_skills:
                memory.record_use(skill_name, proven)

    if ctx.enrich and report.verdict in ("malicious", "suspicious"):
        from src.app.sandtrap.enrich import enrich as run_enrichment

        ctx.emit("stage", {"name": "enrich", "detail": "deep-research agent writes a cited threat brief (this can take a few minutes)"})
        report.threat_brief = run_enrichment(report)
    ctx.report = report
    paths = write_report(report, ctx.out_dir)
    ctx.emit("verdict", {"verdict": report.verdict, "score": report.score, "terminal": render_terminal(report)})
    return {"stage": "done", "report_paths": {k: str(v) for k, v in paths.items()}}


def build_graph(checkpointer):
    graph = StateGraph(ScanState)
    graph.add_node("setup", node_setup)
    graph.add_node("baseline", node_baseline)
    graph.add_node("analyst", node_analyst)
    graph.add_node("learn", node_learn)
    graph.add_node("remediate", node_remediate)
    graph.add_node("finalize", node_finalize)
    graph.add_edge(START, "setup")
    graph.add_edge("setup", "baseline")
    graph.add_edge("baseline", "analyst")
    graph.add_edge("analyst", "learn")
    graph.add_edge("learn", "remediate")
    graph.add_edge("remediate", "finalize")
    graph.add_edge("finalize", END)
    return graph.compile(checkpointer=checkpointer)


_GRAPH = None
CHECKPOINT_BACKEND = "memory"


def _checkpointer():
    """LangGraph checkpoints in the Neon Postgres provisioned through Stripe Projects; in-memory if it is unreachable."""
    global CHECKPOINT_BACKEND
    url = os.getenv("NEON_POSTGRES_CONNECTION_STRING", "").strip().strip("'\"")
    if url:
        try:
            import psycopg
            from langgraph.checkpoint.postgres import PostgresSaver
            from psycopg.rows import dict_row

            conn = psycopg.connect(url, autocommit=True, prepare_threshold=0, row_factory=dict_row, connect_timeout=10)
            saver = PostgresSaver(conn)
            saver.setup()
            CHECKPOINT_BACKEND = "neon-postgres"
            return saver
        except Exception as exc:
            logger.warning("neon_checkpointer_unavailable", error=f"{type(exc).__name__}: {str(exc)[:160]}")
    return MemorySaver()


def get_graph():
    global _GRAPH
    if _GRAPH is None:
        _GRAPH = build_graph(_checkpointer())
        logger.info("scan_graph_ready", checkpoints=CHECKPOINT_BACKEND)
    return _GRAPH


def scan(target: str, emit: Emit | None = None, out_dir: str = "out", probe_budget: int = 5, remediate: bool = True, use_memory: bool = True,
         use_cache: bool = False, enrich: bool = False) -> Report:
    """Run a full scan. The sandbox is always destroyed, even when a node raises."""
    emit = emit or (lambda kind, data: None)
    if use_cache and use_memory and not target.startswith("pypi:") and Path(target).is_dir():
        hit = get_memory().cached(sha256=_dir_hash(Path(target)))
        if hit is not None:  # identical sample hash analysed before: no sandbox needed
            emit("cache", {"job": hit.job, "verdict": hit.verdict})
            hit.from_cache = True
            return hit
    job = uuid.uuid4().hex[:10]
    ctx = RunCtx(job=job, target=target, emit=emit, out_dir=out_dir, probe_budget=probe_budget, remediate=remediate, use_memory=use_memory, enrich=enrich)
    RUNS[job] = ctx
    tracer = _langfuse()
    try:
        with tracer.trace_langgraph_agent(
            "sandtrap_scan", input_data={"target": target}, session_id=job, tags=["sandtrap"],
            metadata={"model": settings.LLM_MODEL, "probe_budget": str(probe_budget)},
        ) as observation:
            handler = tracer.get_callback_handler()
            config = {"configurable": {"thread_id": job}, "callbacks": [handler] if handler else []}
            get_graph().invoke({"job": job, "target": target}, config=config)
            if observation is not None and ctx.report is not None:
                observation.update(output={"verdict": ctx.report.verdict, "score": ctx.report.score, "lure_only": ctx.report.lure_only})
        return ctx.report
    finally:
        if ctx.session is not None:
            ctx.session.destroy()
        RUNS.pop(job, None)
        tracer.flush()
        logger.info("scan_finished", job=job, target=target)
