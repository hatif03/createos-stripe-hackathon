"""Deploy the FastAPI app (src/app) to a long-lived CreateOS sandbox with a public URL, WITHOUT any credentials (hackathon-built).

The deployed copy has no CreateOS key, LLM key or database URL, so it serves the API shell, /docs and /health but cannot run scans (those
need the author's credentials and would spend quota); run scans locally. The sandbox is named `sandtrap-rptapi-*`, which `gc` leaves alone
(`gc --all` removes it). Usage: uv run python scripts/deploy_app.py
"""
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from src.app.sandtrap.sandbox import SandboxSession, make_client  # noqa: E402

PORT = 8000
s = SandboxSession(label="rptapi", shape="s-1vcpu-2gb", client=make_client())
s.create()
s.instance.set_ingress(True)
print("sandbox", s.id, flush=True)
s.put_dir(ROOT / "src", "/root/app/src")
s.put("/root/app/pyproject.toml", (ROOT / "pyproject.toml").read_bytes())
s.put("/root/app/uv.lock", (ROOT / "uv.lock").read_bytes())
s.run("cd /root/app && touch README.md && (curl -LsSf https://astral.sh/uv/install.sh | sh) >/tmp/uv.log 2>&1; "
      "nohup /root/.local/bin/uv sync --python 3.13 --no-dev >/tmp/sync.log 2>&1 &", timeout=120)
for n in range(60):  # up to about 9 minutes
    time.sleep(10)
    done = s.run("pgrep -f 'uv sync' >/dev/null && echo busy || echo done").stdout.strip()
    print(n, done, s.run("tail -c 150 /tmp/sync.log | tr '\\n' ' '").stdout.strip(), flush=True)
    if done == "done":
        break
s.run(f"cd /root/app && APP_ENV=production nohup .venv/bin/uvicorn src.app.main:app --host 0.0.0.0 --port {PORT} >/tmp/app.log 2>&1 &", timeout=60)
time.sleep(15)
print("app log:", s.run("tail -c 600 /tmp/app.log").stdout, flush=True)
try:
    s.instance.wait_for_port(PORT, timeout=60)
    print("DEPLOYED:", s.instance.preview_url(PORT) + "/docs", flush=True)
except Exception as exc:
    print("NOT UP:", exc, flush=True)
