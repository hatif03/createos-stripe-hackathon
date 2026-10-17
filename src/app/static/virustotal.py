"""Reputation lookup by hash.

Only the SHA-256 is looked up (``GET /files/{hash}``, never an upload), "not found" is a normal answer, and the module does nothing
without ``VIRUSTOTAL_API_KEY``.
"""

from __future__ import annotations

import os

import httpx

from src.app.core.common.logging import logger
from src.app.sandtrap.types import StaticFinding

URL = "https://www.virustotal.com/api/v3/files/{sha256}"


def lookup(sha256: str) -> list[StaticFinding]:
    key = os.getenv("VIRUSTOTAL_API_KEY", "")
    if not key or not sha256:
        return []
    try:
        response = httpx.get(URL.format(sha256=sha256), headers={"x-apikey": key, "accept": "application/json"}, timeout=20)
    except httpx.HTTPError as exc:
        logger.warning("virustotal_unreachable", error=str(exc)[:120])
        return []
    if response.status_code == 404:
        return [StaticFinding(source="virustotal", title="hash unknown to VirusTotal", severity="low", detail=sha256)]
    if response.status_code != 200:
        logger.warning("virustotal_error", status=response.status_code)
        return []
    stats = response.json().get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
    bad = int(stats.get("malicious", 0)) + int(stats.get("suspicious", 0))
    if bad == 0:
        return []
    return [StaticFinding(source="virustotal", title=f"flagged by {bad} VirusTotal engines", severity="high" if bad >= 5 else "medium", detail=sha256)]
