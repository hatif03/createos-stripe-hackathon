"""Shared data contracts for Sandtrap (hackathon-built). Every module exchanges these models."""

from __future__ import annotations

from typing import Any, Literal

from pydantic import BaseModel, Field

EventKind = Literal[
    "dns_query",  # data: name:str, answered:bool                       (from the DNS stub log)
    "net_connect",  # data: addr:str, port:int, blocked:bool            (strace connect(), non-loopback)
    "sink_request",  # data: host:str, method:str, path:str, body:str, canaries:list[str]
    "exec",  # data: argv:list[str], suspicious:bool                    (child process spawned by the sample)
    "file_read_sensitive",  # data: path:str, canary:str|None            (credential-like path opened)
    "file_write",  # data: path:str, persistence:bool                    (write outside the work dir)
    "file_delete",  # data: path:str, self:bool
    "chmod_exec",  # data: path:str                                      (chmod +x then exec of the same path)
    "gate_exit",  # data: reason:str                                     (quick clean exit, no behaviour; heuristic)
    "sleep",  # data: seconds:float                                      (long sleep/clock probe: time-bomb hint)
]

Severity = Literal["low", "medium", "high"]
Proof = Literal["proof", "intent", "signal"]
Verdict = Literal["clean", "suspicious", "malicious", "inconclusive"]


class Event(BaseModel):
    t: float = 0.0  # seconds since the probe started
    pid: int = 0
    kind: EventKind
    data: dict[str, Any] = Field(default_factory=dict)
    round: int = 0


class Probe(BaseModel):
    """One experiment the analyst asks the sandbox to run."""

    round: int = 0
    label: str = "baseline"
    env: dict[str, str] = Field(default_factory=dict)
    lure: bool = False  # DNS stub answers 127.0.0.1 + HTTP sink listens (else DNS answers NXDOMAIN)
    sink_reply: str = '{"ok": true}'
    clock_offset_days: int = 0  # `date -s` forward this many days before the run
    driver_code: str = ""  # python source the agent wrote (import / exercise the package)
    timeout_s: int = 45


class ProbeResult(BaseModel):
    probe: Probe
    exit_code: int = -1
    stdout: str = ""
    stderr: str = ""
    events: list[Event] = Field(default_factory=list)
    duration_ms: int = 0
    sandbox_id: str = ""
    error: str = ""  # harness-level failure (driver crashed before the sample ran, sandbox error, ...)


class AttackRef(BaseModel):
    id: str
    name: str
    url: str


class Evidence(BaseModel):
    round: int
    event_index: int
    excerpt: str


class Finding(BaseModel):
    id: str
    title: str
    severity: Severity
    proof: Proof
    attack: list[AttackRef] = Field(default_factory=list)
    evidence: list[Evidence] = Field(default_factory=list)


class StaticFinding(BaseModel):
    """Output of the static layer (capa/strings/VT), merged into the same ATT&CK table."""

    source: Literal["capa", "strings", "virustotal", "heuristic"]
    title: str
    severity: Severity = "low"
    attack_ids: list[str] = Field(default_factory=list)  # e.g. ["T1552.004"]
    detail: str = ""


class EgressStep(BaseModel):
    phase: str
    rules: list[str]
    note: str = ""


class AttemptLog(BaseModel):
    round: int
    label: str
    exit_code: int
    note: str  # what failed / what the agent changed


class Report(BaseModel):
    job: str
    target: str
    target_kind: str = "package"
    sha256: str = ""
    created_at: str = ""
    verdict: Verdict = "inconclusive"
    score: int = 0
    confidence: Literal["low", "medium", "high"] = "low"
    findings: list[Finding] = Field(default_factory=list)
    static_findings: list[StaticFinding] = Field(default_factory=list)
    rounds: list[ProbeResult] = Field(default_factory=list)
    baseline_only: list[str] = Field(default_factory=list)  # behaviours seen only in the baseline run
    lure_only: list[str] = Field(default_factory=list)  # behaviours seen only after the agent's lure (evasion evidence)
    hypotheses: list[str] = Field(default_factory=list)
    summary: str = ""
    attempts: list[AttemptLog] = Field(default_factory=list)
    egress_timeline: list[EgressStep] = Field(default_factory=list)
    patch_diff: str = ""
    remediation: str = ""  # e.g. "exfiltration no longer observed under the same lure"
    capture_method: str = "strace"
    model: str = ""
    llm_calls: int = 0
    sandbox_ids: list[str] = Field(default_factory=list)
    destroyed: bool = False
    limitations: list[str] = Field(default_factory=list)
    report_url: str = ""
    intel: list[str] = Field(default_factory=list)  # threat-memory hits ("known indicator ... seen in N earlier scans")
    used_skills: list[str] = Field(default_factory=list)  # skills retrieved from earlier scans and tried first
    learned_skills: list[str] = Field(default_factory=list)  # skills the agent wrote after this scan
    threat_brief: str = ""  # cited research on the indicators (deep-research agent), when enabled
    from_cache: bool = False
