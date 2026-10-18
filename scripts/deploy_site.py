"""Deploy the evidence site (docs/PROOF.md + docs/proof/) to a long-lived CreateOS sandbox with a public URL (hackathon-built).

Reuses the report host from hosting.py (sandbox `sandtrap-rpt-*`, ingress on, python http.server on 8080). Do not run `gc --all` afterwards:
it removes this sandbox. Usage: uv run python scripts/deploy_site.py
"""
import re
import sys
from pathlib import Path

import markdown

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from src.app.sandtrap.hosting import HOST_LABEL, PORT, _existing  # noqa: E402
from src.app.sandtrap.sandbox import SandboxSession, make_client  # noqa: E402

CSS = ("body{margin:0 auto;max-width:1100px;padding:24px;background:#0d1117;color:#e6edf3;font:16px/1.55 system-ui,Segoe UI,Arial,sans-serif}"
       "a{color:#58a6ff}table{border-collapse:collapse;width:100%;font-size:14px}th,td{border:1px solid #30363d;padding:6px 10px;text-align:left}"
       "th{background:#161b22}code,pre{background:#161b22;border-radius:5px;padding:2px 6px}pre{padding:12px;overflow:auto}img{max-width:100%}")

body = markdown.markdown((ROOT / "docs" / "PROOF.md").read_text(encoding="utf-8"), extensions=["tables", "fenced_code"])
intro = ("<p><b>Sandtrap</b>: an AI analyst that lures evasive code into revealing itself inside CreateOS sandboxes, proves exfiltration with canary "
         "credentials, and patches it. Source: <a href='https://github.com/hatif03/createos-stripe-hackathon'>github.com/hatif03/createos-stripe-hackathon</a>. "
         "Below: the evidence (reports are static HTML produced by real scans).</p>")
index = f"<!doctype html><meta charset=utf-8><meta name=viewport content='width=device-width,initial-scale=1'><title>Sandtrap evidence</title><style>{CSS}</style>{intro}{body}"
index = re.sub(r'href="\.\./README\.md[^"]*"', 'href="https://github.com/hatif03/createos-stripe-hackathon#limitations"', index)

client = make_client()
instance = _existing(client)
session = SandboxSession(label=HOST_LABEL, shape="s-1vcpu-256mb", client=client)
if instance is None:
    session.create()
else:
    if "running" not in str(instance.data.status).lower():
        instance.resume()
    session.instance = instance
    session._wait_running()
session.instance.set_ingress(True)
session.put("/srv/index.html", index.encode("utf-8"))
for f in sorted((ROOT / "docs" / "proof").rglob("*")):
    if f.is_file():
        session.put(f"/srv/proof/{f.relative_to(ROOT / 'docs' / 'proof').as_posix()}", f.read_bytes())
alive = session.run(f"(echo > /dev/tcp/127.0.0.1/{PORT}) >/dev/null 2>&1 && echo up || echo down").stdout.strip()
if alive != "up":
    session.run(f"cd /srv && nohup python3 -m http.server {PORT} --bind 0.0.0.0 >/tmp/http.log 2>&1 &")
    session.instance.wait_for_port(PORT, timeout=30)
print("DEPLOYED:", session.instance.preview_url(PORT) + "/")
