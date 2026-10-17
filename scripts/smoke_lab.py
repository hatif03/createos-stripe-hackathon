"""Live smoke test of the lab: install a fixture, lock egress, run baseline + lure probes, score. (hackathon-built)"""
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from src.app.sandtrap.lab import Lab, default_driver, local_modules  # noqa: E402
from src.app.sandtrap.sandbox import REGISTRY_EGRESS, SandboxSession, gc  # noqa: E402
from src.app.sandtrap.score import score  # noqa: E402
from src.app.sandtrap.types import Probe  # noqa: E402


def show(result):
    print(f"  [{result.probe.label}] exit={result.exit_code} {result.duration_ms}ms error={result.error!r}")
    print(f"    stdout: {result.stdout.strip()[:200]!r}")
    for e in result.events:
        print(f"    {e.t:7.2f}s {e.kind:20} {str(e.data)[:150]}")


fixture = Path(sys.argv[1])
env = {"CI": "1"} if len(sys.argv) > 2 and sys.argv[2] == "ci" else {}
t0 = time.time()
print("gc removed:", gc())
with SandboxSession("smoke", egress=REGISTRY_EGRESS) as s:
    print(f"sandbox {s.id} up in {time.time()-t0:.1f}s")
    lab = Lab(s)
    inst = lab.install_local(fixture)
    print(f"install ok={inst.ok} exit={inst.exit_code} events={len(inst.events)} ({time.time()-t0:.0f}s)")
    if not inst.ok:
        print(inst.stderr[-800:])
    for e in inst.events[:12]:
        print(f"    install {e.kind:18} {str(e.data)[:120]}")
    print("egress:", s.lock_down())
    driver = default_driver(local_modules(fixture))
    rounds = []
    base = lab.run_probe(Probe(round=0, label="baseline", driver_code=driver)); show(base); rounds.append(base)
    lure = lab.run_probe(Probe(round=1, label="lure", lure=True, env=env, driver_code=driver)); show(lure); rounds.append(lure)
    r = score(rounds)
    print("VERDICT:", r.verdict, r.confidence, r.score, "| lure_only:", r.lure_only)
    for f in r.findings:
        print("  -", f.severity, f.proof, f.title, [a.id for a in f.attack])
print(f"done in {time.time()-t0:.0f}s; leftover:", gc())
