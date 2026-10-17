# Demo video script (3:00 max, a team member on camera)

Pre-flight (do once, off camera): `uv run python -m src.cli.sandtrap gc --all`, `uv run python -m src.cli.sandtrap doctor` is all green,
terminal font 18 pt, run `uv run python -m src.cli.sandtrap scan fixtures/gated-stealer --publish` once so the public report host is warm,
keep a pre-run copy of the benchmark (`docs/BENCHMARK.md`) and of the fork-and-race output (`scripts/race_smoke.py`) open in tabs.

| Time | On screen | Say |
| --- | --- | --- |
| 0:00-0:20 | **You on camera**, then screen share | "`npm install` and `pip install` run a stranger's code. A normal sandbox runs it once, sees nothing, and calls it clean. Real malware knows it is being watched and stays quiet. Sandtrap is an AI analyst that notices, builds a trap, and proves it." |
| 0:20-0:45 | `stripe projects status` then `sandtrap doctor` | "The whole stack came from Stripe Projects: CreateOS for the sandboxes, Neon for the agent's checkpoints, credentials synced to `.env`. Every line the agent writes runs in a CreateOS sandbox." |
| 0:45-1:55 | `scan fixtures/gated-stealer` (live, about 40 s) | "The package is installed under strace with the firewall allowing only the registries, then locked. The baseline run: it reads nothing, exits silently, and a plain sandbox would stop here. Watch the agent: it reads the code, hypothesises the gate, DNS must resolve and CI must be set, builds a fake internet on loopback, reruns. The sink catches our planted canary credentials: proof. The verdict is computed by code from events, not by the model. Now the agent patches the package and re-runs the same attack: nothing leaves, smoke test passes." |
| 1:55-2:15 | Open the **public report URL** printed by `--publish` | "The report is hosted by another CreateOS sandbox with a public URL. This panel is the evidence: behaviour that only appeared after the agent changed the environment, the firewall timeline, ATT&CK techniques, the patch." |
| 2:15-2:40 | `docs/BENCHMARK.md` table, then the fork-and-race output | "Same run scored two ways: plain sandbox versus Sandtrap. When the gate is unknown, the agent forks the sandbox three times and races hypotheses in parallel; forks, pause and public URLs all work on the free plan." |
| 2:40-2:55 | `scan c:fixtures/c/gated_beacon.c` summary or the MCP call from Claude Code | "It also compiles and analyses native binaries with capa inside the sandbox, and coding agents can call it over MCP before they install anything." |
| 2:55-3:00 | Back to camera | "Samples are harmless fixtures, the internet is blocked, credentials are fake canaries. Limits are documented. Code and docs are in the repo." |

Fallbacks: if the live scan stalls, show `out/<job>/report.html` from a pre-run and say so; if the LLM is down set `LLM_PROVIDER=k2` and rerun.
Record each segment as a clip as soon as it works, then stitch.
