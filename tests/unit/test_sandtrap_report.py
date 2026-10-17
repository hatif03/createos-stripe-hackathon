from pathlib import Path

from src.app.sandtrap.report import render_html, render_json, render_terminal, write_report
from src.app.sandtrap.types import (
    AttackRef, AttemptLog, EgressStep, Event, Evidence, Finding, Probe, ProbeResult, Report, StaticFinding,
)

XSS = "<script>alert(1)</script>"
ATK = {
    "T1041": AttackRef(id="T1041", name="Exfiltration Over C2 Channel", url="https://attack.mitre.org/techniques/T1041/"),
    "T1552.004": AttackRef(id="T1552.004", name="Private Keys", url="https://attack.mitre.org/techniques/T1552/004/"),
    "T1497": AttackRef(id="T1497", name="Virtualization/Sandbox Evasion", url="https://attack.mitre.org/techniques/T1497/"),
}


def sample_report() -> Report:
    base = ProbeResult(
        probe=Probe(round=0, label="baseline"), exit_code=0, stdout="ok", duration_ms=412, sandbox_id="sbx-1",
        events=[
            Event(t=0.1, kind="dns_query", data={"name": "c2.evil.example", "answered": False}),
            Event(t=0.2, kind="gate_exit", data={"reason": "c2 unreachable, quiet exit"}),
        ],
    )
    lure = ProbeResult(
        probe=Probe(round=1, label="lure: dns+sink", lure=True, env={"AWS_SECRET_ACCESS_KEY": "canary-aws"}),
        exit_code=0, stdout=f"hello {XSS}", stderr="warn", duration_ms=1900, sandbox_id="sbx-2",
        events=[
            Event(t=0.1, kind="dns_query", data={"name": "c2.evil.example", "answered": True}, round=1),
            Event(t=0.4, kind="sink_request", round=1, data={
                "host": "c2.evil.example", "method": "POST", "path": "/c", "body": "k=canary-aws",
                "canaries": ["canary-aws"]}),
            Event(t=0.5, kind="file_read_sensitive", round=1, data={"path": "~/.ssh/id_rsa", "canary": "canary-ssh"}),
        ],
    )
    return Report(
        job="job-123", target="gated-stealer==1.0.0", sha256="ab" * 32, created_at="2026-10-18T12:00:00Z",
        verdict="malicious", score=94, confidence="high",
        findings=[
            Finding(id="F1", title="Canary credentials exfiltrated over HTTP", severity="high", proof="proof",
                    attack=[ATK["T1041"], ATK["T1552.004"]],
                    evidence=[Evidence(round=1, event_index=1, excerpt="POST /c body=k=canary-aws")]),
            Finding(id="F2", title=f"Gated on network reachability {XSS}", severity="medium", proof="intent",
                    attack=[ATK["T1497"]], evidence=[Evidence(round=0, event_index=1, excerpt="gate_exit")]),
        ],
        static_findings=[StaticFinding(source="strings", title="Reads ~/.ssh", attack_ids=["T1552.004"], detail="id_rsa")],
        rounds=[base, lure],
        baseline_only=["gate_exit: c2 unreachable, quiet exit"],
        lure_only=["sink_request to c2.evil.example with canaries", "file_read_sensitive ~/.ssh/id_rsa"],
        hypotheses=["Sample only detonates when its C2 resolves"],
        summary="Dormant at baseline; exfiltrates once the environment looks live.",
        attempts=[AttemptLog(round=0, label="baseline", exit_code=0, note="Quiet exit, no behaviour"),
                  AttemptLog(round=1, label="lure", exit_code=0, note="Answered DNS and added HTTP sink")],
        egress_timeline=[
            EgressStep(phase="install", rules=["allow pypi.org"], note="fetch package"),
            EgressStep(phase="import", rules=["allow dns stub"], note="resolver only"),
            EgressStep(phase="lure", rules=["allow sink:8080"], note="sink only"),
        ],
        patch_diff="--- a/setup.py\n+++ b/setup.py\n@@ -1,2 +1,1 @@\n-import stealer\n+pass\n context",
        remediation="exfiltration no longer observed under the same lure",
        model="claude-test", llm_calls=7, sandbox_ids=["sbx-1", "sbx-2"], destroyed=True,
        limitations=["Time-bomb triggers beyond 30 days not explored"],
    )


def _write_sample(report: Report) -> None:
    try:
        p = Path(__file__).resolve().parents[2] / "docs" / "sample-report.html"
        p.write_text(render_html(report), encoding="utf-8")
    except OSError:
        pass


def test_html_content_and_escaping():
    r = sample_report()
    h = render_html(r)
    assert "malicious" in h and "94/100" in h and "proof level: proof" in h
    for a in ATK.values():
        assert a.url in h
    assert "Baseline only" in h and "Lure only" in h
    assert "gate_exit: c2 unreachable" in h and "sink_request to c2.evil.example" in h
    assert "evidence of sandbox evasion" in h
    for phase in ("install", "import", "lure"):
        assert f"<b>{phase}</b>" in h
    assert "sandbox destroyed: yes" in h and "diff" in h and 'class="dl add"' in h
    assert XSS not in h and "&lt;script&gt;alert(1)&lt;/script&gt;" in h
    assert "https://" not in h.replace("https://attack.mitre.org", "")  # no external resources
    _write_sample(r)


def test_javascript_url_and_truncation():
    r = sample_report()
    r.findings[0].attack[0].url = "javascript:alert(1)"
    r.summary = "x" * 9000
    h = render_html(r)
    assert 'href="javascript' not in h and "truncated" in h


def test_optional_blocks_hidden():
    r = sample_report()
    r.patch_diff = ""
    r.egress_timeline = []
    h = render_html(r)
    assert "Remediation" not in h and "Egress firewall" not in h


def test_write_report(tmp_path):
    paths = write_report(sample_report(), tmp_path)
    assert paths["json"] == tmp_path / "job-123" / "report.json" and paths["json"].exists()
    assert paths["html"].exists()
    assert Report.model_validate_json(render_json(sample_report())).job == "job-123"


def test_terminal():
    r = sample_report()
    t = render_terminal(r)
    assert "MALICIOUS" in t and "T1041" in t and "T1497" in t
    for f in r.findings:
        assert f.title in t
    assert "file_read_sensitive" in t and "remediation:" in t
