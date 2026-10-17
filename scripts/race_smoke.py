"""Live smoke test of fork-and-race: three NODE_ENV guesses in three forked sandboxes at once. (hackathon-built)"""
import logging
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
for noisy in ("httpcore", "httpx", "openai", "langfuse", "urllib3", "hpack"):
    logging.getLogger(noisy).setLevel(logging.WARNING)

from src.app.sandtrap.lab import Lab, default_driver, local_modules  # noqa: E402
from src.app.sandtrap.race import run_parallel  # noqa: E402
from src.app.sandtrap.sandbox import REGISTRY_EGRESS, SandboxSession, gc  # noqa: E402
from src.app.sandtrap.types import Probe  # noqa: E402

fixture = Path("fixtures/hash-gated-stealer")
gc()
t0 = time.time()
with SandboxSession("race", egress=REGISTRY_EGRESS) as s:
    lab = Lab(s)
    print("install ok:", lab.install_local(fixture).ok, f"{time.time()-t0:.0f}s")
    s.lock_down()
    driver = default_driver(local_modules(fixture))
    probes = [Probe(round=i + 1, label=f"race-{v}", lure=True, env={"NODE_ENV": v}, driver_code=driver)
              for i, v in enumerate(["staging", "production", "dev"])]
    t1 = time.time()
    results = run_parallel(lab, probes, lambda k, d: print("  event:", k, d))
    print(f"race took {time.time()-t1:.1f}s")
    for r in results:
        proof = any(e.kind == "sink_request" and e.data.get("canaries") for e in r.events)
        print(f"  {r.probe.label:16} sandbox={r.sandbox_id[-8:]} exit={r.exit_code} events={len(r.events)} PROOF={proof} err={r.error!r}")
    print("related forks:", [i[-8:] for i in s.related_ids])
    print("timeline:", [(x.phase, x.rules) for x in s.egress_timeline])
print(f"total {time.time()-t0:.0f}s; leftover gc:", gc())
