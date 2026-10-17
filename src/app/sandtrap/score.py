"""Deterministic verdict + score from probe events. Never reads stdout/stderr (prompt-injection safe)."""

from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, Field

from .attack import KIND_ATTACK, attack_ref
from .types import Event, Evidence, Finding, ProbeResult, Severity, StaticFinding, Verdict

REGISTRY_HOSTS = {"pypi.org", "files.pythonhosted.org", "registry.npmjs.org"}
_WEIGHT = {"high": 30, "medium": 12, "low": 4}


class ScoreResult(BaseModel):
    findings: list[Finding] = Field(default_factory=list)
    verdict: Verdict = "inconclusive"
    score: int = 0  # display only
    confidence: Literal["low", "medium", "high"] = "low"
    baseline_only: list[str] = Field(default_factory=list)
    lure_only: list[str] = Field(default_factory=list)


def _host(e: Event) -> str:
    d = e.data
    return str(d.get("host") or d.get("name") or d.get("addr") or "").lower()


def _outbound(e: Event) -> bool:
    """Outbound attempt to a non-registry host."""
    if e.kind == "net_connect" and (e.data.get("port") == 53 or str(e.data.get("addr", "")).startswith("169.254.")):
        return False  # resolver / platform metadata traffic, not sample behaviour
    return e.kind in ("net_connect", "dns_query", "sink_request") and _host(e) not in REGISTRY_HOSTS


def _key(e: Event) -> str:
    """Behaviour key: kind + main data field."""
    d = e.data
    match e.kind:
        case "sink_request":
            return f"sink_request:{d.get('host', '')}"
        case "net_connect":
            return f"net_connect:{d.get('addr', '')}:{d.get('port', '')}"
        case "dns_query":
            return f"dns_query:{d.get('name', '')}"
        case "exec":
            return f"exec:{' '.join(map(str, d.get('argv', [])))}"
        case "sleep":
            return f"sleep:{d.get('seconds', '')}"
        case "gate_exit":
            return "gate_exit"  # durations in the reason text must not look like different behaviour
        case _:
            return f"{e.kind}:{d.get('path', '')}"


def _excerpt(e: Event) -> str:
    s = _key(e)
    if e.kind == "sink_request" and e.data.get("canaries"):
        s += f" canaries={','.join(map(str, e.data['canaries']))}"
    return s[:120]


def _is_lure(r: ProbeResult) -> bool:
    p = r.probe
    return bool(p.lure or p.env or p.clock_offset_days)


def _ssh(text: str) -> bool:
    t = text.lower()
    return "ssh" in t or "id_rsa" in t or "id_ed25519" in t


def _ids(*kinds: str) -> list[str]:
    return [i for k in kinds for i in KIND_ATTACK[k]]


class _Findings:
    """Aggregates evidence per finding id, merging ATT&CK ids."""

    def __init__(self) -> None:
        self.items: dict[str, Finding] = {}

    def add(self, fid: str, title: str, sev: Severity, proof: str, ids: list[str], ev: Evidence | None = None) -> None:
        f = self.items.setdefault(fid, Finding(id=fid, title=title, severity=sev, proof=proof))  # type: ignore[arg-type]
        have = {a.id for a in f.attack}
        f.attack += [attack_ref(i) for i in dict.fromkeys(ids) if i not in have]
        if ev:
            f.evidence.append(ev)


def _scan_round(r: ProbeResult, fs: _Findings) -> None:
    rnd = r.probe.round

    def ev(i: int, e: Event) -> Evidence:
        return Evidence(round=rnd, event_index=i, excerpt=_excerpt(e))

    indexed = list(enumerate(r.events))
    if r.probe.label == "install" and not any(e.kind == "file_read_sensitive" for _, e in indexed):
        # pip talks to the registry CDN over 443 (the firewall only allows registry hosts); that is not an attack signal
        indexed = [(i, e) for i, e in indexed if not (e.kind == "net_connect" and e.data.get("port") == 443)]
    reads = [(i, e) for i, e in indexed if e.kind == "file_read_sensitive"]
    out = [(i, e) for i, e in indexed if _outbound(e)]

    for i, e in indexed:
        d = e.data
        if e.kind == "sink_request" and d.get("canaries"):
            kinds = ["exfil"] + ["cred_ssh" if _ssh(str(c)) else "cred_file" for c in d["canaries"]]
            fs.add("canary_exfil", "Canary credentials exfiltrated", "high", "proof", _ids(*kinds), ev(i, e))
        elif e.kind == "file_write" and d.get("persistence"):
            p = str(d.get("path", "")).lower()
            kind = "persist_cron" if "cron" in p else "persist_ssh" if "authorized_keys" in p else "persist"
            fs.add("persistence", "Persistence mechanism written", "high", "intent", _ids(kind), ev(i, e))
        elif e.kind == "chmod_exec":
            fs.add("dropper", "Dropped file made executable and run", "high", "intent", _ids("dropper"), ev(i, e))
        elif e.kind == "exec" and d.get("suspicious"):
            fs.add("suspicious_exec", "Suspicious process spawned", "medium", "signal", _ids("exec"), ev(i, e))
        elif e.kind == "file_delete" and d.get("self"):
            fs.add("self_delete", "Sample deleted itself", "medium", "signal", _ids("self_delete"), ev(i, e))
        elif e.kind == "sleep" and float(d.get("seconds", 0) or 0) >= 300:
            fs.add("time_bomb", f"Long sleep ({d.get('seconds')}s): possible time bomb", "low", "signal",
                   _ids("time_bomb"), ev(i, e))
        elif e.kind == "gate_exit":
            fs.add("gate_exit", "Exited quickly without behaviour; may be gated", "low", "signal",
                   _ids("evasion"), ev(i, e))

    if reads and out:
        kinds = ["exfil"] + ["cred_ssh" if _ssh(f"{e.data.get('path', '')} {e.data.get('canary') or ''}") else "cred_file"
                             for _, e in reads]
        for i, e in reads + out:
            fs.add("cred_read_outbound", "Credential file read followed by outbound attempt", "high", "intent",
                   _ids(*kinds), ev(i, e))
    elif out:
        for i, e in out:
            fs.add("outbound", "Outbound network attempt to non-registry host", "medium", "signal", _ids("c2"), ev(i, e))


def _relevant(e: Event) -> bool:
    """Only behaviour that can be a sample's own doing counts when diffing baseline against lure. The analyst's driver commands
    (`find`, `node -e ...`), temp-file names and log files differ between probes by construction and are not evasion."""
    if e.kind in ("file_read_sensitive", "chmod_exec"):
        return True
    if e.kind == "file_write":
        return bool(e.data.get("persistence"))
    return e.kind in ("net_connect", "dns_query", "sink_request") and _outbound(e)


def _compare(rounds: list[ProbeResult], fs: _Findings) -> tuple[list[str], list[str]]:
    """Return (lure_only, baseline_only) behaviour keys; adds the evasion finding."""
    ok = [r for r in rounds if not r.error]
    base = next((r for r in ok if r.probe.label == "baseline"), None) or min(
        ok, key=lambda r: r.probe.round, default=None
    )
    lures = [r for r in ok if r is not base and _is_lure(r)]
    if base is None or not lures:
        return [], []
    bkeys = {_key(e) for e in base.events if _relevant(e)}
    lkeys = {_key(e) for r in lures for e in r.events if _relevant(e)}
    lure_only, baseline_only = sorted(lkeys - bkeys), sorted(bkeys - lkeys)
    hits = [(r, i, e) for r in lures for i, e in enumerate(r.events) if _relevant(e) and _key(e) in lure_only]
    # a downloader that merely connects once DNS resolves (nvm, rustup) is already reported as "outbound"; evasion needs the sample to
    # do something sensitive (read credentials, persist, drop and run a file) or to leak a canary only under the lure
    if any(e.kind not in ("net_connect", "dns_query", "sink_request") or e.data.get("canaries") for _, _, e in hits):
        proof = "proof" if any(e.kind == "sink_request" and e.data.get("canaries") for _, _, e in hits) else "intent"
        for r, i, e in hits:
            fs.add("lure_only", "Behaviour only appears under lure (sandbox evasion)", "high", proof,
                   _ids("evasion"), Evidence(round=r.probe.round, event_index=i, excerpt=_excerpt(e)))
    return lure_only, baseline_only


def score(
    rounds: list[ProbeResult],
    static_findings: list[StaticFinding] | None = None,
    canary_tokens: list[str] | None = None,  # noqa: ARG001  (reserved: sink events already carry matched canaries)
    executed: bool | None = None,
) -> ScoreResult:
    """Derive findings, verdict, score and confidence from probe events and static findings."""
    fs = _Findings()
    for r in rounds:
        _scan_round(r, fs)
    # a quick quiet exit is only suspicious if no lure/environment experiment ran: if the agent also tried to trigger
    # the sample and it stayed quiet, "does nothing" is the honest reading (reported with low confidence)
    quiet_behaviour = {"net_connect", "sink_request", "file_read_sensitive", "file_write", "exec", "chmod_exec", "file_delete", "sleep"}
    if "gate_exit" in fs.items and any(
        _is_lure(r) and not r.error and r.exit_code not in (-1, 124, 137) and not any(e.kind in quiet_behaviour for e in r.events)
        for r in rounds
    ):
        del fs.items["gate_exit"]
    lure_only, baseline_only = _compare(rounds, fs)
    for n, s in enumerate(static_findings or []):
        fs.add(f"static_{n}_{s.source}", s.title, s.severity, "signal", s.attack_ids)

    findings = list(fs.items.values())
    mediums = [f for f in findings if f.severity == "medium"]
    if executed is None:
        executed = any(r.exit_code != -1 and not r.error for r in rounds)
    all_errored = not rounds or all(r.error for r in rounds)

    if any(f.severity == "high" and f.proof in ("proof", "intent") for f in findings):
        verdict: Verdict = "malicious"
    elif len(mediums) >= 2 or any(f.severity == "high" for f in findings):
        verdict = "suspicious"
    elif not executed or all_errored or findings:
        # ponytail: low/single-medium findings (gate, time bomb, static hints) stay inconclusive, never clean
        verdict = "inconclusive"
    else:
        verdict = "clean"

    confidence = (
        "high" if any(f.proof == "proof" for f in findings)
        else "medium" if any(f.proof == "intent" for f in findings)
        else "low"
    )
    total = sum(_WEIGHT[f.severity] + (10 if f.proof == "proof" else 0) for f in findings)
    return ScoreResult(
        findings=findings, verdict=verdict, score=min(total, 100), confidence=confidence,
        baseline_only=baseline_only, lure_only=lure_only,
    )
