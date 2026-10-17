"""Email intake (hackathon-built): the agent owns an AgentMail inbox provisioned through Stripe Projects.

Email ``pypi:<package>`` (or ``fixture:<name>`` for the demo fixtures) to the inbox; Sandtrap scans it in a CreateOS sandbox and replies
with the verdict, ATT&CK techniques, the evasion evidence and a public report link. Targets go through the same strict allow-list as
the HTTP API; replies contain only Sandtrap's own structured fields, never text taken from a sample.
"""

from __future__ import annotations

import json
import os
import re
import time
from pathlib import Path
from typing import Callable

import httpx

from src.app.core.common.logging import logger
from src.app.sandtrap.jobs import resolve_target

BASE = "https://api.agentmail.to/v0"
TARGET = re.compile(r"\b((?:pypi|fixture):[A-Za-z0-9][A-Za-z0-9._=-]{0,60})")
MAX_SCANS_PER_HOUR = 6


def api_key() -> str:
    return os.getenv("AGENTMAIL_AGENTMAIL_API_KEY") or os.getenv("AGENTMAIL_API_KEY", "")


def resolve_target_safe(token: str) -> str | None:
    try:
        return resolve_target(token)
    except ValueError:
        return None


def extract_target(text: str) -> str | None:
    """First `pypi:` / `fixture:` token that survives the API allow-list, else None."""
    for match in TARGET.finditer(text or ""):
        try:
            return resolve_target(match.group(1))
        except ValueError:
            continue
    return None


class Mailbox:
    def __init__(self, key: str = "", username: str = "sandtrap-scan", state_path: str = "out/mail_state.json",
                 client: httpx.Client | None = None) -> None:
        self.username = username
        self.state_path = Path(state_path)
        self.http = client or httpx.Client(timeout=30.0)
        self.key = key or api_key()
        if not self.key:
            raise RuntimeError("no AgentMail key: run `stripe projects add agentmail/api`")
        self.state = json.loads(self.state_path.read_text()) if self.state_path.exists() else {"processed": [], "scans": []}

    # -- API ---------------------------------------------------------------------------------------------------
    def _call(self, method: str, path: str, **kwargs):
        response = self.http.request(method, f"{BASE}{path}", headers={"Authorization": f"Bearer {self.key}"}, **kwargs)
        if response.status_code >= 400:
            raise RuntimeError(f"agentmail {method} {path}: HTTP {response.status_code} {response.text[:160]}")
        return response.json() if response.content else {}

    def _save(self) -> None:
        self.state_path.parent.mkdir(parents=True, exist_ok=True)
        self.state_path.write_text(json.dumps(self.state))

    def inbox(self) -> dict:
        """The scan inbox: created on first use, then reused."""
        if self.state.get("inbox"):
            return self.state["inbox"]
        try:
            box = self._call("POST", "/inboxes", json={"username": self.username, "display_name": "Sandtrap scanner"})
        except RuntimeError:  # username taken by an earlier run: find it
            found = next((b for b in self._call("GET", "/inboxes", params={"limit": 100}).get("inboxes", [])
                          if b.get("email", "").startswith(self.username + "@")), None)
            if found is None:
                raise
            box = found
        self.state["inbox"] = {"inbox_id": box["inbox_id"], "email": box["email"]}
        self._save()
        return self.state["inbox"]

    def new_messages(self) -> list[dict]:
        box = self.inbox()
        listing = self._call("GET", f"/inboxes/{box['inbox_id']}/messages", params={"limit": 20, "ascending": "true"})
        seen = set(self.state["processed"])
        out = []
        for item in listing.get("messages", []):
            labels = item.get("labels") or []
            if item["message_id"] in seen or "sent" in labels or box["email"] in item.get("from", ""):
                continue
            out.append(item)
        return out

    def message(self, message_id: str) -> dict:
        return self._call("GET", f"/inboxes/{self.inbox()['inbox_id']}/messages/{message_id}")

    def reply(self, message_id: str, text: str) -> None:
        self._call("POST", f"/inboxes/{self.inbox()['inbox_id']}/messages/{message_id}/reply", json={"text": text})

    def mark(self, message_id: str) -> None:
        self.state["processed"].append(message_id)
        self._save()

    def scan_budget_ok(self) -> bool:
        now = time.time()
        self.state["scans"] = [t for t in self.state.get("scans", []) if now - t < 3600]
        return len(self.state["scans"]) < MAX_SCANS_PER_HOUR


def summarize(report, report_url: str = "", label: str = "") -> str:
    lines = [
        f"Sandtrap verdict for {label or report.target}: {report.verdict.upper()} (confidence {report.confidence}, score {report.score}/100)",
        "",
    ]
    if report.findings:
        lines.append("Findings:")
        for f in report.findings[:8]:
            techniques = ", ".join(a.id for a in f.attack)
            lines.append(f"  - [{f.severity}/{f.proof}] {f.title}" + (f" ({techniques})" if techniques else ""))
    if report.lure_only:
        lines += ["", "Behaviour that appeared only after the agent changed the environment (sandbox-evasion evidence):"]
        lines += [f"  + {x}" for x in report.lure_only[:6]]
    if report.remediation:
        lines += ["", f"Remediation: {report.remediation[:400]}"]
    if report_url:
        lines += ["", f"Full report: {report_url}"]
    lines += ["", "Analysed in an isolated CreateOS sandbox with the real internet blocked; planted credentials are fake canaries."]
    return "\n".join(lines)


def handle_message(box: Mailbox, item: dict, scan_fn: Callable | None = None, publish: bool = True) -> str:
    """Process one inbound email; returns the reply text that was sent."""
    full = box.message(item["message_id"])
    body = f"{full.get('subject', '')}\n{full.get('extracted_text') or full.get('text') or ''}"
    target = extract_target(body)
    if target is None:
        reply = ("Sandtrap could not find a scannable target. Send a message containing `pypi:<package>` "
                 "(for example `pypi:requests`) and I will analyse it in a CreateOS sandbox.")
    elif not box.scan_budget_ok():
        reply = "Sandtrap is rate limited (6 scans per hour). Please try again later."
    else:
        if scan_fn is None:
            from src.app.sandtrap.graph import scan as scan_fn  # lazy: heavy import
        box.state["scans"].append(time.time())
        report = scan_fn(target, out_dir="out", probe_budget=4, remediate=True)
        url = ""
        if publish:
            try:
                from src.app.sandtrap.hosting import publish_report

                url = publish_report(Path("out") / report.job)
            except Exception as exc:
                logger.warning("mail_publish_failed", error=str(exc)[:160])
        reply = summarize(report, url, label=next((m.group(1) for m in TARGET.finditer(body) if resolve_target_safe(m.group(1)) == target), ""))
    box.reply(item["message_id"], reply)
    box.mark(item["message_id"])
    return reply


def run(once: bool = False, interval: int = 10, publish: bool = True, echo: Callable[[str], None] = print) -> None:
    box = Mailbox()
    echo(f"Sandtrap inbox: {box.inbox()['email']}  (email `pypi:<package>` to get a verdict)")
    while True:
        for item in box.new_messages():
            echo(f"inbound: {item.get('subject', '')!r} from {item.get('from', '')}")
            try:
                handle_message(box, item, publish=publish)
                echo("  replied")
            except Exception as exc:
                logger.warning("mail_handle_failed", error=f"{type(exc).__name__}: {str(exc)[:200]}")
                box.mark(item["message_id"])  # never loop forever on a poison message
        if once:
            return
        time.sleep(interval)
