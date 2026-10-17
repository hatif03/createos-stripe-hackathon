"""Threat Memory: scan cache, IOC store and learned-skill library for Sandtrap (stdlib sqlite3 only)."""

from __future__ import annotations

import ipaddress
import json
import os
import re
import sqlite3
import threading
import time
from pathlib import Path

from pydantic import BaseModel, Field

from .types import Report

DEFAULT_DB = "out/threat_memory.db"
CACHE_TTL_S = 24 * 3600
REGISTRY_HOSTS = {"pypi.org", "files.pythonhosted.org", "registry.npmjs.org"}
STOPWORDS = {
    "a", "an", "and", "are", "as", "at", "be", "by", "for", "from", "if", "in", "is", "it", "of", "on",
    "or", "the", "to", "unless", "until", "when", "with", "this", "that", "then", "only", "not", "no",
}  # fmt: skip

_SCHEMA = """
CREATE TABLE IF NOT EXISTS scans (
  id INTEGER PRIMARY KEY AUTOINCREMENT, job TEXT, target TEXT, sha256 TEXT, verdict TEXT,
  confidence TEXT, score INTEGER, created_at REAL, report TEXT);
CREATE INDEX IF NOT EXISTS scans_sha ON scans(sha256);
CREATE INDEX IF NOT EXISTS scans_target ON scans(target);
CREATE TABLE IF NOT EXISTS iocs (
  value TEXT PRIMARY KEY, kind TEXT, first_seen REAL, last_seen REAL, seen_count INTEGER, last_verdict TEXT);
CREATE TABLE IF NOT EXISTS ioc_jobs (
  value TEXT, job TEXT, verdict TEXT, ts REAL, PRIMARY KEY (value, job));
CREATE TABLE IF NOT EXISTS skills (
  name TEXT PRIMARY KEY, description TEXT, signs TEXT, lure TEXT, notes TEXT,
  created_at TEXT, uses INTEGER, successes INTEGER);
"""


class Skill(BaseModel):
    name: str
    description: str = ""
    signs: list[str] = Field(default_factory=list)
    # probe knobs: {"lure": bool, "env": {...}, "clock_offset_days": int, "sink_reply": str, "driver_hint": str}
    lure: dict = Field(default_factory=dict)
    notes: str = ""
    created_at: str = ""
    uses: int = 0
    successes: int = 0


def _stem(w: str) -> str:
    for suf in ("ing", "es", "ed", "s"):
        if w.endswith(suf) and len(w) - len(suf) >= 3:
            return w[: -len(suf)]
    return w


def _tokens(text: str) -> set[str]:
    return {_stem(w) for w in re.findall(r"[a-z0-9_]+", text.lower()) if w not in STOPWORDS and len(w) > 1}


def _kind(value: str) -> str:
    try:
        ipaddress.ip_address(value)
        return "ip"
    except ValueError:
        return "domain"


def _norm_host(raw: str) -> str:
    h = str(raw or "").strip().lower().rstrip(".")
    if h.count(":") == 1:  # host:port (a bare IPv6 has several colons)
        h = h.rsplit(":", 1)[0]
    return h


class ThreatMemory:
    def __init__(self, path: str | os.PathLike | None = None) -> None:
        self.path = str(path or os.environ.get("SANDTRAP_MEMORY_DB") or DEFAULT_DB)
        if self.path != ":memory:":
            Path(self.path).parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.Lock()
        self._db = sqlite3.connect(self.path, check_same_thread=False)
        self._db.row_factory = sqlite3.Row
        with self._lock:
            self._db.executescript(_SCHEMA)
            self._db.commit()

    def _q(self, sql: str, args: tuple = ()) -> list[sqlite3.Row]:
        with self._lock:
            return self._db.execute(sql, args).fetchall()

    def _w(self, sql: str, args: tuple = ()) -> None:
        with self._lock:
            self._db.execute(sql, args)
            self._db.commit()

    # ---- scan cache ----
    def remember_scan(self, report: Report) -> None:
        self._w(
            "INSERT INTO scans (job,target,sha256,verdict,confidence,score,created_at,report) VALUES (?,?,?,?,?,?,?,?)",
            (report.job, report.target, report.sha256, report.verdict, report.confidence, report.score,
             time.time(), report.model_dump_json()),
        )  # fmt: skip

    def cached(self, sha256: str = "", target: str = "") -> Report | None:
        if sha256:
            rows = self._q(
                "SELECT report FROM scans WHERE sha256=? AND verdict!='inconclusive' ORDER BY id DESC LIMIT 1",
                (sha256,),
            )
        elif target.startswith("pypi:"):
            rows = self._q(
                "SELECT report FROM scans WHERE target=? AND verdict!='inconclusive' AND created_at>=? "
                "ORDER BY id DESC LIMIT 1",
                (target, time.time() - CACHE_TTL_S),
            )
        else:
            return None
        return Report.model_validate_json(rows[0]["report"]) if rows else None

    # ---- IOCs ----
    def extract_iocs(self, report: Report) -> list[dict]:
        found: dict[str, str] = {}
        for rnd in report.rounds:
            for ev in rnd.events:
                key = {"dns_query": "name", "sink_request": "host", "net_connect": "addr"}.get(ev.kind)
                if not key:
                    continue
                v = _norm_host(ev.data.get(key, ""))
                if not v or v in REGISTRY_HOSTS or v in ("localhost", "127.0.0.1", "::1"):
                    continue
                found.setdefault(v, _kind(v))
        return [{"value": v, "kind": k} for v, k in found.items()]

    def remember_iocs(self, report: Report) -> None:
        now = time.time()
        with self._lock:
            for ioc in self.extract_iocs(report):
                v = ioc["value"]
                new = self._db.execute(
                    "INSERT OR IGNORE INTO ioc_jobs (value,job,verdict,ts) VALUES (?,?,?,?)",
                    (v, report.job, report.verdict, now),
                ).rowcount
                if not new:
                    self._db.execute(
                        "UPDATE ioc_jobs SET verdict=?, ts=? WHERE value=? AND job=?", (report.verdict, now, v, report.job)
                    )
                self._db.execute(
                    "INSERT INTO iocs (value,kind,first_seen,last_seen,seen_count,last_verdict) VALUES (?,?,?,?,1,?) "
                    "ON CONFLICT(value) DO UPDATE SET last_seen=?, last_verdict=?, seen_count=seen_count+?",
                    (v, ioc["kind"], now, now, report.verdict, now, report.verdict, new),
                )
            self._db.commit()

    def known_iocs(self, values: list[str]) -> list[dict]:
        if not values:
            return []
        marks = ",".join("?" * len(values))
        rows = self._q(
            f"SELECT value,kind,seen_count,first_seen,last_seen,last_verdict FROM iocs WHERE value IN ({marks})",
            tuple(values),
        )
        return [dict(r) for r in rows]

    def annotate(self, report: Report) -> list[str]:
        out = []
        for ioc in self.extract_iocs(report):
            rows = self._q(
                "SELECT verdict FROM ioc_jobs WHERE value=? AND job!=? ORDER BY ts DESC", (ioc["value"], report.job)
            )
            if rows:
                n = len(rows)
                out.append(
                    f"known indicator {ioc['value']} (seen in {n} earlier scan{'s' if n != 1 else ''}, "
                    f"last verdict {rows[0]['verdict']})"
                )
        return out

    # ---- skill library ----
    def save_skill(self, skill: Skill) -> None:
        created = skill.created_at or time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
        self._w(
            "INSERT INTO skills (name,description,signs,lure,notes,created_at,uses,successes) VALUES (?,?,?,?,?,?,?,?) "
            "ON CONFLICT(name) DO UPDATE SET description=excluded.description, signs=excluded.signs, "
            "lure=excluded.lure, notes=excluded.notes",  # counters and created_at are kept
            (skill.name, skill.description, json.dumps(skill.signs), json.dumps(skill.lure), skill.notes,
             created, skill.uses, skill.successes),
        )  # fmt: skip

    @staticmethod
    def _skill(r: sqlite3.Row) -> Skill:
        return Skill(
            name=r["name"], description=r["description"], signs=json.loads(r["signs"]), lure=json.loads(r["lure"]),
            notes=r["notes"], created_at=r["created_at"], uses=r["uses"], successes=r["successes"],
        )  # fmt: skip

    def list_skills(self) -> list[Skill]:
        return [self._skill(r) for r in self._q("SELECT * FROM skills ORDER BY name")]

    def relevant_skills(self, text: str, limit: int = 3) -> list[Skill]:
        want, low = _tokens(text), text.lower()
        scored = []
        for s in self.list_skills():
            have = _tokens(" ".join([s.name, s.description, *s.signs]))
            score = len(want & have) + sum(2 for p in s.signs if p.strip() and p.lower() in low)
            if score > 0:
                scored.append((score, s))
        scored.sort(key=lambda x: (-x[0], -x[1].successes, x[1].name))  # stable, deterministic
        return [s for _, s in scored[:limit]]

    def record_use(self, name: str, success: bool) -> None:
        self._w("UPDATE skills SET uses=uses+1, successes=successes+? WHERE name=?", (1 if success else 0, name))

    def render_skills_for_prompt(self, skills: list[Skill]) -> str:
        if not skills:
            return ""
        lines = ["Skills learned from earlier scans (try these first, but verify):"]
        for s in skills:
            lines.append(f"- {s.name}: {s.description}".rstrip(": "))
            lines.append(f"  signs: {'; '.join(s.signs)}")
            lines.append(f"  lure knobs: {json.dumps(s.lure, sort_keys=True)}")
            lines.append(f"  worked {s.successes}/{s.uses} times")
        return "\n".join(lines)

    def stats(self) -> dict:
        n = lambda t: self._q(f"SELECT COUNT(*) c FROM {t}")[0]["c"]  # noqa: E731
        return {"scans": n("scans"), "iocs": n("iocs"), "skills": n("skills")}


_singleton: ThreatMemory | None = None
_singleton_lock = threading.Lock()


def get_memory() -> ThreatMemory:
    global _singleton
    with _singleton_lock:
        if _singleton is None:
            _singleton = ThreatMemory()
        return _singleton
