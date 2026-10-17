"""Publish a finished report at a public CreateOS URL (hackathon-built).

A tiny long-lived sandbox (``sandtrap-rpt-*``) with ingress enabled serves ``/srv`` with ``python -m http.server``; each report is
uploaded as ``/srv/<job>/index.html``. The URL is ``https://<sandbox>-8080.app.sb.createos.sh/<job>/``. Reports contain only fake
canary tokens and escaped sample output.
"""

from __future__ import annotations

from pathlib import Path

from createos.models import ListSandboxesOptions

from src.app.core.common.logging import logger
from src.app.sandtrap.sandbox import NAME_PREFIX, SandboxSession, make_client

HOST_LABEL = "rpt"
PORT = 8080


def _existing(client):
    for instance in client.list_sandboxes(ListSandboxesOptions()):
        status = str(getattr(instance.data, "status", "")).lower()
        if (instance.name or "").startswith(f"{NAME_PREFIX}{HOST_LABEL}") and "destroy" not in status:
            return instance
    return None


def publish_report(report_dir: str | Path) -> str:
    """Upload ``report.html``/``report.json`` from ``report_dir`` and return the public URL."""
    report_dir = Path(report_dir)
    job = report_dir.name
    client = make_client()
    instance = _existing(client)
    if instance is not None and "running" not in str(instance.data.status).lower():
        instance.resume()
    session = SandboxSession(label=HOST_LABEL, shape="s-1vcpu-256mb", client=client)
    if instance is None:
        session.create()
    else:
        session.instance = instance
        session._wait_running()
    session.instance.set_ingress(True)
    session.put(f"/srv/{job}/index.html", (report_dir / "report.html").read_bytes())
    session.put(f"/srv/{job}/report.json", (report_dir / "report.json").read_bytes())
    alive = session.run(f"(echo > /dev/tcp/127.0.0.1/{PORT}) >/dev/null 2>&1 && echo up || echo down").stdout.strip()
    if alive != "up":
        session.run(f"cd /srv && nohup python3 -m http.server {PORT} --bind 0.0.0.0 >/tmp/http.log 2>&1 &")
        session.instance.wait_for_port(PORT, timeout=30)
    url = f"{session.instance.preview_url(PORT)}/{job}/"
    logger.info("report_published", url=url, sandbox_id=session.id)
    return url
