"""Threat-brief enrichment with the deep-research agent (supervisor + parallel researchers, running on Gemini with Google Search grounding). Optional (``--enrich``): slow (1-4 minutes) and web-dependent, so it never sits on the verdict's critical path.
A brief without any source URL is withheld, because an unsourced security brief is worse than none."""

from __future__ import annotations

import asyncio
import re
import uuid

from src.app.agents.open_deep_research.factory import make_deep_research_agent
from src.app.core.common.logging import logger
from src.app.core.common.model.message import Message
from src.app.sandtrap.types import Report

URL = re.compile(r"https?://[^\s)\]>\"']+")


def build_prompt(report: Report) -> str:
    techniques = sorted({a.id + " " + a.name for f in report.findings for a in f.attack})
    indicators = sorted({e.data.get("name") or e.data.get("host") for r in report.rounds for e in r.events
                         if e.kind in ("dns_query", "sink_request") and (e.data.get("name") or e.data.get("host"))})
    return (
        "Write a short cited threat brief (max 350 words) for a security engineer. A sandbox analysis found a software package that "
        f"stays silent until its environment looks real and then steals credentials. Observed ATT&CK techniques: {techniques}. "
        f"Analyst summary: {report.summary[:600]}. Indicators (may be fictional test domains; say so if no public record exists): "
        f"{indicators[:6]}. Cover: (1) real-world supply-chain campaigns using the same evasion and exfiltration approach, with dates; "
        "(2) how defenders detect and contain it; (3) concrete mitigations for npm/PyPI users. Every factual claim needs a source URL. "
        "If sources cannot be found, say exactly that."
    )


async def _research(prompt: str) -> str:
    agent = await make_deep_research_agent(None, None)
    messages = await agent.agent_invoke([Message(role="user", content=prompt)], f"enrich-{uuid.uuid4().hex[:8]}")
    return str(messages[-1].content) if messages else ""


def enrich(report: Report, timeout_s: float = 300.0) -> str:
    """Returns the brief ('' when unavailable or unsourced)."""
    try:
        brief = asyncio.run(asyncio.wait_for(_research(build_prompt(report)), timeout_s))
    except Exception as exc:
        logger.warning("enrich_failed", error=f"{type(exc).__name__}: {str(exc)[:200]}")
        return ""
    if not URL.search(brief):
        logger.warning("enrich_unsourced_brief_withheld")
        return "Brief withheld: the research agent returned no source URLs, so its claims cannot be verified."
    return brief.strip()
