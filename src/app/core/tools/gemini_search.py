"""Web search through Gemini's built-in Google Search grounding (Vertex AI), returning text with source URLs.

Replaces the scraping-based DuckDuckGo tool when Gemini is the LLM provider: it needs no extra key (gcloud login),
does not depend on flaky scraping backends, and every answer carries real citations from ``groundingMetadata``.
When nothing is retrieved the tool says so explicitly so the agent cannot silently answer from memory.
"""

import asyncio
from typing import List

import httpx
from langchain_core.tools import tool

from src.app.core.common.config import settings
from src.app.core.common.logging import logger
from src.app.core.llm.gemini_vertex import GcloudToken

_TOKEN = GcloudToken(settings.GCLOUD_ACCOUNT, settings.GEMINI_ACCESS_TOKEN)
NO_SOURCES = (
    "NO SOURCES RETRIEVED for this query. Do not state facts from memory; "
    "report that no verifiable source was found."
)


def _endpoint() -> str:
    host = "aiplatform.googleapis.com" if settings.GEMINI_LOCATION == "global" else f"{settings.GEMINI_LOCATION}-aiplatform.googleapis.com"
    return (
        f"https://{host}/v1/projects/{settings.GEMINI_PROJECT}/locations/{settings.GEMINI_LOCATION}"
        f"/publishers/google/models/{settings.GEMINI_MODEL}:generateContent"
    )


async def _one(client: httpx.AsyncClient, query: str) -> str:
    body = {
        "contents": [{"role": "user", "parts": [{"text": f"Search the web and answer factually with specifics and dates: {query}"}]}],
        "tools": [{"googleSearch": {}}],
        "generationConfig": {"maxOutputTokens": 2000},
    }
    try:
        response = await client.post(_endpoint(), json=body, headers={"Authorization": f"Bearer {_TOKEN.get()}"})
        response.raise_for_status()
        candidate = (response.json().get("candidates") or [{}])[0]
    except Exception as error:
        logger.warning("gemini_search_failed", query=query, error=str(error)[:200])
        return f"--- {query} ---\n{NO_SOURCES} (search error)"
    text = "".join(part.get("text", "") for part in (candidate.get("content") or {}).get("parts", [])).strip()
    chunks = (candidate.get("groundingMetadata") or {}).get("groundingChunks") or []
    sources = [(c.get("web") or {}) for c in chunks if c.get("web")]
    if not text or not sources:
        return f"--- {query} ---\n{NO_SOURCES}"
    cited = "\n".join(f"- {s.get('title', 'source')}: {s.get('uri', '')}" for s in sources[:8])
    return f"--- {query} ---\n{text}\n\nSources:\n{cited}"


@tool(description="Web search with cited sources (Google Search via Gemini). Pass several focused queries at once.")
async def gemini_grounded_search(queries: List[str]) -> str:
    """Run web searches and return findings with source URLs.

    Args:
        queries: Focused search queries, executed in parallel.
    """
    async with httpx.AsyncClient(timeout=httpx.Timeout(90.0, connect=15.0)) as client:
        results = await asyncio.gather(*[_one(client, q) for q in queries])
    return "\n\n".join(results)
