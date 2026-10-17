"""Fork-and-race (hackathon-built): test several hypotheses at once.

The parent sandbox is paused (a snapshot of the installed package, canaries and analyzer), cloned into one fork per
experiment, each fork gets its own firewall (everything blocked) and runs its probe in parallel, then the forks are destroyed
and the parent resumes. If the platform refuses concurrent sandboxes the experiments run one after another instead.
"""

from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from typing import Callable

from src.app.core.common.logging import logger
from src.app.sandtrap.lab import Lab
from src.app.sandtrap.sandbox import BLOCK_ALL, SandboxSession
from src.app.sandtrap.types import Probe, ProbeResult

Emit = Callable[[str, dict], None]
MAX_FORKS = 3


def run_parallel(lab: Lab, probes: list[Probe], emit: Emit) -> list[ProbeResult]:
    """Run ``probes`` concurrently in forks of ``lab``'s sandbox (sequentially as a fallback)."""
    probes = probes[:MAX_FORKS]
    if len(probes) <= 1:
        return [lab.run_probe(p) for p in probes]
    parent: SandboxSession = lab.session
    children: list[SandboxSession] = []
    paused = False
    try:
        parent.snapshot()
        paused = True
        emit("race", {"phase": "snapshot", "parent": parent.id, "forks": len(probes)})
        with ThreadPoolExecutor(max_workers=len(probes)) as pool:  # fork in parallel: each clone takes ~5-15 s to wake
            children.extend(pool.map(lambda i: parent.fork(label=f"race{i}", egress=BLOCK_ALL), range(len(probes))))
        parent.related_ids.extend(c.id for c in children)
        emit("race", {"phase": "forked", "children": [c.id for c in children]})
        labs = []
        for child in children:
            child_lab = Lab(child)
            child_lab.token, child_lab.prepared = lab.token, True  # the snapshot already holds analyzer + canaries
            labs.append(child_lab)
        with ThreadPoolExecutor(max_workers=len(probes)) as pool:
            results = list(pool.map(lambda pair: pair[0].run_probe(pair[1]), zip(labs, probes)))
        for child in children:
            parent.egress_timeline.extend(child.egress_timeline)
        emit("race", {"phase": "done", "results": [(r.probe.label, r.exit_code, len(r.events)) for r in results]})
        return results
    except Exception as exc:
        logger.warning("race_fallback_sequential", error=str(exc)[:200])
        emit("race", {"phase": "fallback", "error": f"{type(exc).__name__}: {str(exc)[:160]}"})
        for child in children:
            child.destroy()
        children = []
        if paused:
            try:
                parent.resume()
            except Exception:
                logger.warning("race_resume_failed", exc_info=True)
            paused = False
        return [lab.run_probe(p) for p in probes]
    finally:
        for child in children:
            child.destroy()
        if paused:
            parent.resume()
