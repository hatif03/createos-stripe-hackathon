"""Run the real application on a set of demo targets and keep the evidence (hackathon-built).

For every run it saves, under media/demo/ and docs/proof/demo/<name>/:
  <name>.jsonl            the terminal output with timestamps (rendered into a video by scripts/render_demo.py)
  report.html / .json     the scan report (when the run produced one)
  sandbox-lifecycle.txt   the CreateOS sandbox events from the application log (created, egress set, forked, destroyed) with UTC times
Usage: uv run python scripts/record_demo.py [name ...]
"""
import json
import os
import re
import shutil
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
MEDIA = ROOT / "media" / "demo"
PROOF = ROOT / "docs" / "proof" / "demo"
CLI = ["uv", "run", "python", "-u", "-m", "src.cli.sandtrap"]
ANSI = re.compile(r"\x1b\[[0-9;?]*[A-Za-z]")
STAMP = re.compile(r"\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d\.\d+Z")
EVENTS = ("sandbox_created", "sandbox_forked", "sandbox_egress_set", "sandbox_destroyed", "report_published", "fork_child_parked_resuming")

# name -> (title, command). `{hero_dir}` is filled from the hero run's report folder.
ITEMS = {
    "hero": ("Python package with an environment-gated stealer", CLI + ["scan", "fixtures/gated-stealer", "--publish", "--out", "out/demo"]),
    "npm": ("npm package with a malicious postinstall", CLI + ["scan", "npm:fixtures/npm-postinstall-beacon", "--out", "out/demo"]),
    "elf": ("C program compiled and analysed inside the sandbox (capa)", CLI + ["scan", "c:fixtures/c/gated_beacon.c", "--out", "out/demo"]),
    "script": ("Tampered CI uploader script (Codecov-style)", CLI + ["scan", "script:fixtures/script-ci-uploader/uploader.sh", "--out", "out/demo"]),
    "real": ("A real PyPI package: requests", CLI + ["scan", "pypi:requests", "--out", "out/demo"]),
    "race": ("Fork-and-race: pause, fork three clones, race hypotheses", ["uv", "run", "python", "-u", "scripts/race_smoke.py"]),
    "mcp": ("MCP: a coding agent asks Sandtrap before installing a package", ["uv", "run", "python", "-u", "scripts/mcp_demo.py", "fixture:gated-stealer"]),
    "mail": ("Email intake through AgentMail (Stripe Projects)", ["uv", "run", "python", "-u", "scripts/mail_smoke.py", "fixture:gated-stealer"]),
}


def lifecycle(start: datetime, end: datetime) -> list[str]:
    """CreateOS sandbox events from the application log files, in the run's time window."""
    out = []
    for log in sorted((ROOT / "logs").glob("*.jsonl")):
        for line in log.read_text(encoding="utf-8", errors="ignore").splitlines():
            try:
                text = ANSI.sub("", json.loads(line).get("message", ""))
            except ValueError:
                continue
            m = STAMP.search(text)
            if not m or not any(e in text for e in EVENTS):
                continue
            when = datetime.strptime(m.group(0), "%Y-%m-%dT%H:%M:%S.%fZ").replace(tzinfo=timezone.utc)
            if start <= when <= end:
                keep = " ".join(w for w in text.split() if w.split("=")[0] in ("sandbox_id", "name", "shape", "phase", "rules", "parent", "child", "url", "attempt")
                                or w in EVENTS)
                out.append(f"{m.group(0)}  {keep}")
    return sorted(set(out))


def run(name: str, hero_dir: str = "") -> str:
    title, cmd = ITEMS[name]
    cmd = [c.replace("{hero_dir}", hero_dir) for c in cmd]
    MEDIA.mkdir(parents=True, exist_ok=True)
    env = {**os.environ, "FORCE_COLOR": "1", "TERM": "xterm-256color", "COLORTERM": "truecolor", "COLUMNS": "130", "PYTHONUNBUFFERED": "1",
           "PYTHONUTF8": "1", "CONSOLE_LOG_LEVEL": "WARNING"}
    subprocess.run(CLI + ["gc"], cwd=ROOT, capture_output=True)
    start = datetime.now(timezone.utc)
    t0 = time.perf_counter()
    p = subprocess.Popen(cmd, cwd=ROOT, env=env, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    lines = []
    with (MEDIA / f"{name}.jsonl").open("w", encoding="utf-8") as f:
        f.write(json.dumps({"t": 0, "title": title, "command": " ".join(c for c in cmd[3:] if c not in ("-u", "-m"))}) + "\n")
        for raw in iter(p.stdout.readline, b""):
            text = raw.decode("utf-8", "replace")
            lines.append(text)
            f.write(json.dumps({"t": round(time.perf_counter() - t0, 2), "text": text}) + "\n")
            f.flush()
    p.wait()
    end = datetime.now(timezone.utc)
    seconds = round(time.perf_counter() - t0)
    folder = PROOF / name
    folder.mkdir(parents=True, exist_ok=True)
    joined = ANSI.sub("", "".join(lines))
    m = re.search(r"report:\s+(\S+?)[\\/]report\.html", joined)
    job_dir = ""
    if m:
        job_dir = m.group(1).replace("\\", "/")
        for ext in ("html", "json"):
            src = ROOT / job_dir / f"report.{ext}"
            if src.exists():
                text = re.sub(r"[A-Za-z]:[\\/]+Users[\\/]+[^\\/\"<]+[\\/]+AppData[\\/]+Local[\\/]+Temp[\\/]+", "<tmp>/", src.read_text(encoding="utf-8"))
                (folder / f"report.{ext}").write_text(text, encoding="utf-8", newline="\n")
    events = lifecycle(start.replace(microsecond=0), end)
    (folder / "sandbox-lifecycle.txt").write_text(
        f"# CreateOS sandbox events from the application log for `{name}` (UTC)\n# command: {' '.join(cmd[3:])}\n" + "\n".join(events) + "\n", encoding="utf-8")
    (folder / "meta.json").write_text(json.dumps({
        "name": name, "title": title, "exit_code": p.returncode, "seconds": seconds, "started_utc": start.isoformat(timespec="seconds"),
        "report_dir": job_dir, "sandbox_events": len(events)}, indent=2), encoding="utf-8")
    print(f"[{name}] exit={p.returncode} {seconds}s report={job_dir or '-'} sandbox events={len(events)}", flush=True)
    return job_dir


if __name__ == "__main__":
    names = sys.argv[1:] or list(ITEMS)
    hero_dir = ""
    for n in names:
        d = run(n, hero_dir)
        if n == "hero":
            hero_dir = d
    subprocess.run(CLI + ["gc"], cwd=ROOT, capture_output=True)
