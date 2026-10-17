"""Run Sandtrap on REAL, unmodified software (not our fixtures) and keep the evidence in docs/proof/ (hackathon-built).

Sources: PyPI packages by name, npm tarballs fetched with `npm pack`, and public installer scripts downloaded over HTTPS on the host
(they are only ever executed inside a sandbox with the internet blocked). Usage: uv run python scripts/real_world.py [slug ...]
"""
import hashlib
import json
import logging
import re
import shutil
import subprocess
import sys
import tarfile
import tempfile
import time
import traceback
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
for noisy in ("httpcore", "httpx", "openai", "langfuse", "urllib3", "hpack"):
    logging.getLogger(noisy).setLevel(logging.WARNING)

from src.app.sandtrap.graph import scan  # noqa: E402
from src.app.sandtrap.sandbox import gc  # noqa: E402

PROOF = ROOT / "docs" / "proof"
WORK = Path(tempfile.mkdtemp(prefix="sandtrap-real-"))

# slug -> (kind, spec, why it is interesting)
ITEMS = {
    "pypi-six": ("pypi", "six", "tiny, ubiquitous"),
    "pypi-requests": ("pypi", "requests", "the most downloaded HTTP client: legitimately network-capable"),
    "pypi-click": ("pypi", "click", "CLI toolkit, reads environment and terminal state"),
    "pypi-pyyaml": ("pypi", "pyyaml", "contains compiled C extensions"),
    "npm-core-js": ("npm", "core-js@3.38.1", "a real, widely used package that has a real postinstall script"),
    "npm-nodemon": ("npm", "nodemon@3.1.7", "real package with a postinstall script"),
    "script-nvm-install": ("script", "https://raw.githubusercontent.com/nvm-sh/nvm/v0.40.1/install.sh", "real installer people pipe into bash"),
    "script-rustup-init": ("script", "https://raw.githubusercontent.com/rust-lang/rustup/1.27.1/rustup-init.sh", "real installer people pipe into bash"),
}


def fetch_npm(spec: str) -> str:
    out = WORK / spec.replace("@", "_")
    out.mkdir()
    tgz = subprocess.run(["npm", "pack", spec, "--silent"], cwd=out, capture_output=True, text=True, shell=True, check=True).stdout.strip().splitlines()[-1]
    with tarfile.open(out / tgz) as t:
        t.extractall(out)
    return f"npm:{out / 'package'}"


def fetch_script(url: str) -> str:
    out = WORK / Path(url).parent.name
    out.mkdir(exist_ok=True)
    path = out / Path(url).name
    path.write_bytes(urllib.request.urlopen(url, timeout=30).read())
    return f"script:{path}"


names = sys.argv[1:] or list(ITEMS)
gc()
PROOF.mkdir(parents=True, exist_ok=True)
index_path = PROOF / "real-world.json"
index = {r["slug"]: r for r in json.loads(index_path.read_text())} if index_path.exists() else {}
for slug in names:
    kind, spec, why = ITEMS[slug]
    t = time.time()
    try:
        target = f"pypi:{spec}" if kind == "pypi" else fetch_npm(spec) if kind == "npm" else fetch_script(spec)
        r = scan(target, out_dir=str(ROOT / "out" / "real"), probe_budget=5, remediate=False, use_memory=False)
    except Exception as exc:
        traceback.print_exc()
        index[slug] = {"slug": slug, "kind": kind, "spec": spec, "why": why, "verdict": "ERROR", "error": f"{type(exc).__name__}: {str(exc)[:200]}"}
        print(index[slug], flush=True)
        continue
    src = ROOT / "out" / "real" / r.job
    for ext in ("html", "json"):  # the report names the temp folder the target was fetched into: keep the host's user name out of the repo
        text = (src / f"report.{ext}").read_text(encoding="utf-8")
        text = re.sub(r"[A-Za-z]:(?:\\\\|\\|/)Users(?:\\\\|\\|/)[^\\/\"<]+(?:\\\\|\\|/)AppData(?:\\\\|\\|/)Local(?:\\\\|\\|/)Temp(?:\\\\|\\|/)", "<tmp>/", text)
        (PROOF / f"{slug}.{ext}").write_text(text, encoding="utf-8", newline="\n")
    probes = [x for x in r.rounds if x.probe.label not in ("install", "baseline")]
    index[slug] = {
        "slug": slug, "kind": kind, "spec": spec, "why": why, "verdict": r.verdict, "score": r.score, "confidence": r.confidence,
        "probes": len(probes), "seconds": round(time.time() - t), "findings": [f.title for f in r.findings][:8],
        "sha256": r.sha256, "created_at": r.created_at, "model": r.model, "destroyed": r.destroyed, "summary": r.summary[:400],
    }
    print(json.dumps(index[slug]), flush=True)
    index_path.write_text(json.dumps(list(index.values()), indent=2), encoding="utf-8")
index_path.write_text(json.dumps(list(index.values()), indent=2), encoding="utf-8")
print("\n" + "\n".join(f"{x['slug']:22}{x['verdict']:14}{x.get('score', '')}" for x in index.values()))
gc()
