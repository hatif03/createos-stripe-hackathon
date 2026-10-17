"""Sandtrap MCP server (stdio): scan a package in a sandbox and read back reports.

Add to Claude Code:

    claude mcp add sandtrap -- uv run python -m src.mcp.sandtrap_server

Targets are limited to `fixture:<name>` and `pypi:<name>[==version]`.
"""

import re
from pathlib import Path

from mcp.server.mcpserver import MCPServer  # mcp 2.x name of FastMCP (mcp.server.fastmcp is gone)

from src.app.sandtrap.jobs import resolve_target
from src.app.sandtrap.report import _best_proof
from src.app.sandtrap.types import Report

OUT_DIR = Path("out")
mcp_server = MCPServer("sandtrap")


def summarize(r: Report, html_path: Path | None = None) -> str:
    lines = [f"verdict: {r.verdict} (score {r.score}/100)", f"confidence: {r.confidence}", f"proof level: {_best_proof(r)}"]
    lines.append("findings:" if r.findings else "findings: none")
    for f in r.findings:
        ids = ", ".join(a.id for a in f.attack)
        lines.append(f"  - {f.title}" + (f" [{ids}]" if ids else ""))
    if r.lure_only:
        lines.append("lure_only (seen only after the lure): " + "; ".join(r.lure_only))
    if r.remediation:
        lines.append(f"remediation: {r.remediation}")
    if html_path:
        lines.append(f"report: {html_path}")
    return "\n".join(lines)


@mcp_server.tool()
def scan_package(target: str, probe_budget: int = 4) -> str:
    """Scan `fixture:<name>` or `pypi:<name>[==version]` in a sandbox; blocks until done. Returns a verdict summary."""
    try:
        resolved = resolve_target(target)
    except ValueError as exc:
        return f"error: {exc}"
    from src.app.sandtrap.graph import scan  # lazy: heavy imports

    report = scan(resolved, out_dir=str(OUT_DIR), probe_budget=max(1, min(8, probe_budget)), remediate=True)
    return summarize(report, (OUT_DIR / report.job / "report.html").resolve())


@mcp_server.tool()
def get_report(job_or_dir: str) -> str:
    """Summarise a finished scan by its job id (hex, as printed in the report)."""
    if not re.fullmatch(r"[a-f0-9]{6,32}", job_or_dir):
        return "error: job id must match [a-f0-9]{6,32}"
    d = OUT_DIR / job_or_dir
    try:
        report = Report.model_validate_json((d / "report.json").read_text(encoding="utf-8"))
    except FileNotFoundError:
        return f"error: no report for job {job_or_dir}"
    return summarize(report, (d / "report.html").resolve())


if __name__ == "__main__":
    mcp_server.run(transport="stdio")
