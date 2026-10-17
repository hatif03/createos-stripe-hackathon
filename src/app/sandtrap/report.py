"""Sandtrap report rendering: self-contained HTML, JSON, and a terminal summary.

All sample-derived text is hostile: every dynamic string goes through `_e` (truncate + html.escape).
"""

from __future__ import annotations

import html
import json
from collections import Counter
from pathlib import Path

from .types import Report

MAX_FIELD = 4000

_VERDICT_NOTE = {
    "clean": "No malicious behaviour observed",
    "suspicious": "Risky behaviour, not conclusively malicious",
    "malicious": "Malicious behaviour demonstrated",
    "inconclusive": "Not enough evidence either way",
}
_VERDICT_ICON = {"clean": "✓", "suspicious": "!", "malicious": "✗", "inconclusive": "?"}


def _e(value: object, limit: int = MAX_FIELD) -> str:
    """Escape any value; truncate long text with a visible note."""
    s = str(value)
    note = ""
    if len(s) > limit:
        note = f"\n… [truncated, {len(s) - limit} more characters]"
        s = s[:limit]
    return html.escape(s, quote=True) + html.escape(note)


def _href(url: str) -> str:
    """Only http(s) links are clickable; anything else (javascript:, data:) is dropped."""
    return html.escape(url, quote=True) if url.lower().startswith(("http://", "https://")) else "#"


def _chip(kind: str, text: str) -> str:
    return f'<span class="chip {_e(kind)}">{_e(text)}</span>'


def _li(items: list[str], empty: str) -> str:
    if not items:
        return f'<li class="empty">{_e(empty)}</li>'
    return "".join(f"<li><code>{_e(i, 600)}</code></li>" for i in items)


def _section(title: str, body: str, open_: bool = True) -> str:
    return f'<details class="card" {"open" if open_ else ""}><summary><h2>{_e(title)}</h2></summary>{body}</details>'


def _timeline(r: Report) -> str:
    items = []
    for a in r.attempts:
        items.append(
            f'<li><span class="dot"></span><div><b>Round {a.round}: {_e(a.label)}</b> '
            f'<span class="muted">exit {a.exit_code}</span><p>{_e(a.note)}</p></div></li>'
        )
    for h in r.hypotheses:
        items.append(f'<li class="hyp"><span class="dot"></span><div><b>Hypothesis</b><p>{_e(h)}</p></div></li>')
    if r.summary:
        items.append(f'<li class="sum"><span class="dot"></span><div><b>Summary</b><p>{_e(r.summary)}</p></div></li>')
    return f'<ol class="timeline">{"".join(items)}</ol>' if items else '<p class="empty">No agent activity recorded.</p>'


def _findings(r: Report) -> str:
    if not r.findings:
        return '<p class="empty">No dynamic findings.</p>'
    rows = []
    for f in r.findings:
        atk = " ".join(
            f'<a class="attack" href="{_href(a.url)}" target="_blank" rel="noopener noreferrer" '
            f'title="{_e(a.name)}">{_e(a.id)}</a>'
            for a in f.attack
        )
        ev = "".join(
            f'<pre class="ev">round {x.round} / event {x.event_index}\n{_e(x.excerpt, 1500)}</pre>' for x in f.evidence
        )
        rows.append(
            f'<tr><td data-l="Finding"><b>{_e(f.title)}</b><div class="muted">{_e(f.id)}</div></td>'
            f'<td data-l="Severity">{_chip("sev-" + f.severity, f.severity)}</td>'
            f'<td data-l="Proof">{_chip("proof-" + f.proof, f.proof)}</td>'
            f'<td data-l="ATT&amp;CK">{atk or "-"}</td><td data-l="Evidence">{ev or "-"}</td></tr>'
        )
    head = "<tr><th>Finding</th><th>Severity</th><th>Proof</th><th>ATT&amp;CK</th><th>Evidence</th></tr>"
    return f'<table class="grid"><thead>{head}</thead><tbody>{"".join(rows)}</tbody></table>'


def _static(r: Report) -> str:
    if not r.static_findings:
        return '<p class="empty">No static findings.</p>'
    rows = "".join(
        f'<tr><td data-l="Source">{_e(s.source)}</td><td data-l="Title"><b>{_e(s.title)}</b></td>'
        f'<td data-l="Severity">{_chip("sev-" + s.severity, s.severity)}</td>'
        f'<td data-l="ATT&amp;CK">{_e(", ".join(s.attack_ids)) or "-"}</td><td data-l="Detail">{_e(s.detail)}</td></tr>'
        for s in r.static_findings
    )
    head = "<tr><th>Source</th><th>Title</th><th>Severity</th><th>ATT&amp;CK</th><th>Detail</th></tr>"
    return f'<table class="grid"><thead>{head}</thead><tbody>{rows}</tbody></table>'


def _egress(r: Report) -> str:
    steps = "".join(
        f'<li><span class="step">{i}</span><div><b>{_e(s.phase)}</b>'
        f'<ul class="rules">{"".join(f"<li><code>{_e(x, 400)}</code></li>" for x in s.rules)}</ul>'
        f'{f"<p class=muted>{_e(s.note)}</p>" if s.note else ""}</div></li>'
        for i, s in enumerate(r.egress_timeline, 1)
    )
    return f'<ol class="stepper">{steps}</ol>'


def _rounds(r: Report) -> str:
    rows = []
    for pr in r.rounds:
        counts = Counter(ev.kind for ev in pr.events)
        cs = " ".join(f'<span class="chip kind">{_e(k)} ×{n}</span>' for k, n in sorted(counts.items())) or "-"
        raw = json.dumps([ev.model_dump() for ev in pr.events], indent=1, default=str)
        detail = (
            f"<details><summary>raw events / stdout / stderr</summary>"
            f"<h4>events</h4><pre>{_e(raw)}</pre><h4>stdout</h4><pre>{_e(pr.stdout)}</pre>"
            f"<h4>stderr</h4><pre>{_e(pr.stderr)}</pre>"
            f"{f'<h4>error</h4><pre>{_e(pr.error)}</pre>' if pr.error else ''}</details>"
        )
        rows.append(
            f'<tr><td data-l="Round">{pr.probe.round}</td>'
            f'<td data-l="Label">{_e(pr.probe.label)}{" " + _chip("lure", "lure") if pr.probe.lure else ""}</td>'
            f'<td data-l="Exit">{pr.exit_code}</td><td data-l="Duration">{pr.duration_ms} ms</td>'
            f'<td data-l="Events">{cs}</td><td data-l="Raw">{detail}</td></tr>'
        )
    head = "<tr><th>Round</th><th>Label</th><th>Exit</th><th>Duration</th><th>Events</th><th>Raw</th></tr>"
    return f'<table class="grid"><thead>{head}</thead><tbody>{"".join(rows)}</tbody></table>'


def _diff(patch: str) -> str:
    lines = []
    for ln in _e(patch, 20000).split("\n"):
        cls = "add" if ln.startswith("+") and not ln.startswith("+++") else (
            "del" if ln.startswith("-") and not ln.startswith("---") else ("hunk" if ln.startswith("@@") else ""))
        lines.append(f'<span class="dl {cls}">{ln}</span>')
    return f'<pre class="diff">{"".join(lines)}</pre>'


_CSS = """
:root{--bg:#f6f7f9;--fg:#15181d;--muted:#5b6470;--card:#fff;--line:#d9dde3;--code:#eef0f3;
--clean:#0f7b3f;--susp:#8a5a00;--mal:#b3261e;--inc:#4b5563;--add:#d9f4e0;--del:#fde0de;--accent:#1d4ed8;--lure:#fff1e6}
@media(prefers-color-scheme:dark){:root{--bg:#0f1216;--fg:#e8ebef;--muted:#9aa4b0;--card:#181c22;--line:#2b323b;--code:#222830;
--clean:#4ade80;--susp:#fbbf24;--mal:#ff7b72;--inc:#a3acb8;--add:#12331f;--del:#43181a;--accent:#7aa2ff;--lure:#3a2412}}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--fg);font:15px/1.5 system-ui,-apple-system,Segoe UI,Roboto,sans-serif}
main{max-width:1100px;margin:0 auto;padding:16px}h1{font-size:1.4rem;margin:.2em 0}h2{display:inline;font-size:1.1rem}h4{margin:.8em 0 .2em}
.muted{color:var(--muted);font-size:.85em}.empty{color:var(--muted);font-style:italic}
code,pre{font-family:ui-monospace,SFMono-Regular,Consolas,monospace;font-size:.85em}
pre{background:var(--code);padding:8px;border-radius:6px;overflow:auto;white-space:pre-wrap;word-break:break-word;max-height:360px;margin:4px 0}
code{background:var(--code);padding:1px 4px;border-radius:4px;word-break:break-all}
.card{background:var(--card);border:1px solid var(--line);border-radius:10px;padding:12px 16px;margin:14px 0}
.card>summary{cursor:pointer;margin-bottom:8px}
.meta{display:grid;grid-template-columns:repeat(auto-fit,minmax(220px,1fr));gap:6px 16px;margin:0}
.meta dt{color:var(--muted);font-size:.8em;text-transform:uppercase}.meta dd{margin:0 0 6px;word-break:break-all}
.hero{display:flex;flex-wrap:wrap;gap:16px;align-items:center}
.badge{border:3px solid currentColor;border-radius:14px;padding:12px 22px;font-weight:800;font-size:2rem;letter-spacing:.04em;text-transform:uppercase}
.badge small{display:block;font-size:.8rem;font-weight:600;letter-spacing:0;text-transform:none}
.v-clean{color:var(--clean)}.v-suspicious{color:var(--susp)}.v-malicious{color:var(--mal)}.v-inconclusive{color:var(--inc)}
.gauge{flex:1;min-width:200px}.bar{height:14px;border-radius:7px;background:var(--code);overflow:hidden;border:1px solid var(--line)}
.bar i{display:block;height:100%;background:currentColor}
.chip{display:inline-block;padding:1px 8px;border-radius:999px;font-size:.78em;font-weight:700;border:1px solid currentColor;margin:1px}
.sev-high,.proof-proof{color:var(--mal)}.sev-medium,.proof-intent{color:var(--susp)}.sev-low,.proof-signal{color:var(--inc)}
.kind{color:var(--accent);font-weight:500}.lure{color:var(--susp)}
a.attack{color:var(--accent);font-weight:600;margin-right:6px}
.timeline,.stepper{list-style:none;padding:0;margin:0}.timeline li{display:flex;gap:10px;padding:6px 0;border-left:2px solid var(--line);margin-left:6px;padding-left:12px;position:relative}
.timeline .dot{position:absolute;left:-7px;top:12px;width:12px;height:12px;border-radius:50%;background:var(--accent)}
.timeline .hyp .dot{background:var(--susp)}.timeline .sum .dot{background:var(--clean)}.timeline p{margin:2px 0}
.diffwrap{display:grid;grid-template-columns:1fr 1fr;gap:12px}
.col{border:2px solid var(--line);border-radius:10px;padding:10px}.col.lure{border-color:var(--mal);background:var(--lure)}
.col h3{margin:0 0 6px;font-size:1rem}.col ul{margin:0;padding-left:18px}
.caption{font-weight:700;margin:10px 0 0;color:var(--mal)}
.stepper li{display:flex;gap:12px;padding:8px 0;border-bottom:1px dashed var(--line)}
.step{flex:none;width:28px;height:28px;border-radius:50%;background:var(--accent);color:var(--card);display:grid;place-items:center;font-weight:700}
.rules{margin:4px 0;padding-left:18px}
table.grid{width:100%;border-collapse:collapse}.grid th,.grid td{text-align:left;vertical-align:top;padding:6px 8px;border-bottom:1px solid var(--line)}
.grid th{font-size:.8em;text-transform:uppercase;color:var(--muted)}
.diff .dl{display:block}.diff .add{background:var(--add)}.diff .del{background:var(--del)}.diff .hunk{color:var(--accent)}
.tools{text-align:right}button{font:inherit;padding:4px 10px;border-radius:6px;border:1px solid var(--line);background:var(--card);color:var(--fg);cursor:pointer}
footer{color:var(--muted);font-size:.85em;margin:20px 0}
@media(max-width:700px){.diffwrap{grid-template-columns:1fr}.badge{font-size:1.5rem}
table.grid thead{display:none}.grid tr{display:block;border-bottom:2px solid var(--line);padding:6px 0}
.grid td{display:block;border:0;padding:2px 0}.grid td::before{content:attr(data-l) ": ";color:var(--muted);font-size:.8em}}
"""

_JS = (
    "function t(o){document.querySelectorAll('details.card').forEach(function(d){d.open=o})}"
    "document.getElementById('ex').onclick=function(){t(true)};"
    "document.getElementById('co').onclick=function(){t(false)};"
)


def render_html(report: Report) -> str:
    r = report
    score = max(0, min(100, r.score))
    meta = [
        ("Target", f"{r.target} ({r.target_kind})"), ("Job", r.job), ("Created", r.created_at or "-"),
        ("SHA-256", r.sha256 or "-"), ("Model", f"{r.model or '-'} ({r.llm_calls} calls)"),
        ("Capture method", r.capture_method),
    ]
    meta_html = "".join(f"<dt>{_e(k)}</dt><dd>{_e(v, 500)}</dd>" for k, v in meta)
    hero = (
        f'<div class="hero"><div class="badge v-{r.verdict}" role="status">'
        f'{_VERDICT_ICON[r.verdict]} {_e(r.verdict)}<small>{_e(_VERDICT_NOTE[r.verdict])}<br>'
        f'proof level: {_e(_best_proof(r))} &middot; confidence: {_e(r.confidence)}</small></div>'
        f'<div class="gauge v-{r.verdict}"><b>Risk score {score}/100</b>'
        f'<div class="bar" role="meter" aria-valuenow="{score}" aria-valuemin="0" aria-valuemax="100">'
        f'<i style="width:{score}%"></i></div></div></div>'
    )
    diff = (
        '<div class="diffwrap"><div class="col"><h3>Baseline only</h3><ul>'
        + _li(r.baseline_only, "nothing unique to baseline")
        + '</ul></div><div class="col lure"><h3>Lure only</h3><ul>'
        + _li(r.lure_only, "nothing unique to lure")
        + "</ul></div></div>"
        '<p class="caption">behaviour that appeared only after the agent changed the environment '
        "= evidence of sandbox evasion</p>"
    )
    parts = [
        _section("What the agent did", _timeline(r)),
        _section("Baseline vs Lure diff", diff),
        _section("Findings", _findings(r)),
        _section("Static findings", _static(r), open_=bool(r.static_findings)),
    ]
    if r.egress_timeline:
        parts.append(_section("Egress firewall timeline", _egress(r)))
    parts.append(_section("Probe rounds", _rounds(r), open_=False))
    if r.patch_diff:
        rem = f"<p>{_e(r.remediation)}</p>" if r.remediation else ""
        parts.append(_section("Remediation", rem + _diff(r.patch_diff)))
    if r.intel or r.used_skills or r.learned_skills or r.from_cache:
        mem = []
        if r.from_cache:
            mem.append("<li>Result served from threat memory (identical sample hash analysed before).</li>")
        mem += [f"<li>{_e(x, 600)}</li>" for x in r.intel]
        mem += [f"<li>Skill from an earlier scan tried first: <b>{_e(x, 200)}</b></li>" for x in r.used_skills]
        mem += [f"<li>New skill learned from this scan: <b>{_e(x, 200)}</b></li>" for x in r.learned_skills]
        parts.append(_section("Threat memory", "<ul>" + "".join(mem) + "</ul>"))
    if r.threat_brief:
        parts.append(_section("Threat brief (web research)", "<pre>" + _e(r.threat_brief, 6000) + "</pre>"))
    if r.limitations:
        parts.append(_section("Limitations", "<ul>" + "".join(f"<li>{_e(x, 800)}</li>" for x in r.limitations) + "</ul>"))
    sbx = ", ".join(r.sandbox_ids) or "-"
    footer = (
        f"<footer>Sandboxes: {_e(sbx, 1000)} &middot; sandbox destroyed: {'yes' if r.destroyed else 'no'}"
        f"{' &middot; ' + _e(r.report_url) if r.report_url else ''}</footer>"
    )
    return (
        '<!doctype html><html lang="en"><head><meta charset="utf-8">'
        '<meta name="viewport" content="width=device-width,initial-scale=1">'
        f"<title>Sandtrap report - {_e(r.target, 200)}</title><style>{_CSS}</style></head><body><main>"
        f'<h1>Sandtrap report</h1><div class="tools"><button id="ex" type="button">Expand all</button> '
        f'<button id="co" type="button">Collapse all</button></div>'
        f'<section class="card"><dl class="meta">{meta_html}</dl></section>'
        f'<section class="card">{hero}</section>{"".join(parts)}{footer}</main>'
        f"<script>{_JS}</script></body></html>"
    )


def _best_proof(r: Report) -> str:
    kinds = {f.proof for f in r.findings}
    return next((p for p in ("proof", "intent", "signal") if p in kinds), "none")


def render_json(report: Report) -> str:
    return report.model_dump_json(indent=2)


def write_report(report: Report, out_dir: str | Path) -> dict[str, Path]:
    d = Path(out_dir) / report.job
    d.mkdir(parents=True, exist_ok=True)
    paths = {"json": d / "report.json", "html": d / "report.html"}
    paths["json"].write_text(render_json(report), encoding="utf-8")
    paths["html"].write_text(render_html(report), encoding="utf-8")
    return paths


def render_terminal(report: Report) -> str:
    r = report
    out = [
        f"SANDTRAP VERDICT: {r.verdict.upper()}  score={r.score}/100  confidence={r.confidence}  proof={_best_proof(r)}",
        f"target: {r.target}  job: {r.job}",
    ]
    if r.findings:
        out.append("findings:")
        for f in r.findings:
            ids = ",".join(a.id for a in f.attack)
            out.append(f"  - [{f.severity}/{f.proof}] {f.title}" + (f"  ({ids})" if ids else ""))
    if r.lure_only:
        out.append("seen only after the lure (evasion evidence):")
        out += [f"  + {x}" for x in r.lure_only]
    if r.remediation:
        out.append(f"remediation: {r.remediation}")
    if r.report_url:
        out.append(f"report: {r.report_url}")
    return "\n".join(out)
