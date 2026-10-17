"""Static layer: capa capability and ATT&CK analysis of compiled targets, run INSIDE the sandbox (never on the host).

capa runs in the analysis sandbox, its JSON is parsed structurally (``meta.attack`` / ``namespace``), empty or failed runs return no
findings instead of crashing, and results become ``StaticFinding`` objects that join the same ATT&CK table as the dynamic evidence.
"""

from __future__ import annotations

import json
from pathlib import Path

from src.app.core.common.logging import logger
from src.app.sandtrap.sandbox import SandboxSession
from src.app.sandtrap.types import StaticFinding

CAPA_ZIP = Path(__file__).resolve().parents[3] / "analyzer" / "bin" / "capa-linux.zip"
# capa tags few rules with ATT&CK; map capability namespaces to the techniques an analyst would write down
NAMESPACE_ATTACK = {
    "communication/c2": ["T1071"],
    "communication/http": ["T1071.001"],
    "communication/dns": ["T1071.004"],
    "host-interaction/environment-variable": ["T1082"],
    "collection/file-managers": ["T1119"],
    "anti-analysis": ["T1497"],
    "persistence": ["T1546"],
}
MEDIUM = ("communication/c2", "anti-analysis", "persistence", "collection", "communication/http", "communication/dns")


def ensure_capa(session: SandboxSession) -> bool:
    """Upload and unpack the capa standalone build (downloaded to analyzer/bin at setup time)."""
    if not CAPA_ZIP.exists():
        logger.warning("capa_zip_missing", path=str(CAPA_ZIP))
        return False
    if session.run("test -x /opt/capa/capa && echo yes").stdout.strip() == "yes":
        return True
    session.put("/tmp/capa.zip", CAPA_ZIP.read_bytes())
    out = session.run("mkdir -p /opt/capa && cd /opt/capa && unzip -o -q /tmp/capa.zip && chmod +x capa && rm /tmp/capa.zip")
    return out.ok


def run_capa(session: SandboxSession, remote_path: str, timeout: float = 240.0) -> list[StaticFinding]:
    """Run capa on a binary inside the sandbox and return static findings (empty list on any failure)."""
    if not ensure_capa(session):
        return []
    out = session.run(f"cd /root/work && /opt/capa/capa -j {remote_path} > /root/work/capa.json 2> /root/work/capa.err", timeout=timeout)
    raw = session.get_text("/root/work/capa.json")
    if not out.ok or not raw.strip():
        logger.warning("capa_failed", exit_code=out.exit_code, err=session.get_text("/root/work/capa.err")[-200:])
        return []
    return parse_capa(raw)


def parse_capa(raw: str) -> list[StaticFinding]:
    try:
        rules = (json.loads(raw) or {}).get("rules") or {}
    except ValueError:
        return []
    findings: list[StaticFinding] = []
    for name, rule in rules.items():
        meta = rule.get("meta", {})
        if meta.get("lib"):  # helper rules (library functions) are noise
            continue
        namespace = meta.get("namespace") or ""
        ids = [a["id"] for a in meta.get("attack", []) if a.get("id")]
        for prefix, mapped in NAMESPACE_ATTACK.items():
            if namespace.startswith(prefix):
                ids += mapped
        severity = "medium" if any(namespace.startswith(m) for m in MEDIUM) else "low"
        findings.append(StaticFinding(
            source="capa", title=f"capability: {name}", severity=severity,
            attack_ids=sorted(set(ids)), detail=namespace,
        ))
    return findings
