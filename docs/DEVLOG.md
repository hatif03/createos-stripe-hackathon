# Development log

Times are PT, 2026-10-17. The build started at 12:44 PT; submissions lock at 17:30 PT. Dead ends are included on purpose.

## Setup (before the build)
- Installed the Stripe CLI and the Projects plugin and the CreateOS CLI (the install script does not support Windows, so the release binary was
  used after verifying its SHA-256). `stripe projects init` needed a browser sign-in and the live-mode account; `add createos/free` and
  `createos/project` then provisioned the sandbox account (free plan).
- Probed the sandbox on the Free plan: strace works as root; the default egress is open and an empty allowlist means "allow all"; `date -s`
  works; `iptables` NAT works; Docker runs inside the sandbox; pause/resume preserve state; **fork works**; a public URL works; `s-1vcpu-2gb`
  is allowed. Spawn time 33-150 ms.
- LLM probing: K2 ignores `response_format: json_schema` and is slow on long contexts; Groq `gpt-oss-120b` works; Gemini models on Vertex AI
  work with the gcloud token (the Generative Language API rejects it with insufficient scopes).

## 12:44-13:50 | core pipeline and the hero scan
- Fixed the data contracts first (`types.py`), then built the offline pieces in parallel (scoring and ATT&CK, the HTML report, the fixtures) while
  writing the serial sandbox parts by hand (`sandbox.py`, `lab.py`, the in-sandbox analyzer).
- **First live run (naive stealer), 15 s end to end:** install under strace with registry-only egress, `set_egress` lock, baseline saw the
  credential read and failed DNS lookups, the lure run captured the POSTed private key with the canary token.
- Bug: the `iptables` catch-all also captured the sandbox's own metadata polling (169.254.169.254): excluded.
- Added the sanitiser, the analyst agent (four tools), the LangGraph pipeline and the CLI. **Hero scan (gated stealer), 28 s:** the agent
  deduced both gates (DNS must resolve, CI must be set), ran one lure probe, the sink captured the AWS and SSH canaries. The model once
  invented a junk environment variable next to `CI=1` (harmless).
- Remediation: the agent writes a patch plus a smoke test, the lab re-runs the same lure; verified (no leak, smoke test passes), 37 s total.

## 13:50-14:10 | benchmark and the scoring bugs it found
- Built `scripts/bench.py`: the same traced run scored as a "plain sandbox" (install + baseline only) versus the full agent.
- Scoring bugs found by real runs, all fixed with tests: a quick quiet exit was flagged on every clean package; a write to a shell startup file
  was only "suspicious"; pip's traffic to the registry CDN and the sandbox resolver counted as outbound; and durations inside event text made the
  baseline-versus-lure comparison invent an evasion finding, turning a clean fixture "malicious" (a false positive, fixed).
- The time-bomb fixture: the plain sandbox is inconclusive, the agent writes a sleep shim itself and proves the exfiltration.

## 13:10-14:10 | fork-and-race (the hard one)
- A fork needs 5-15 s; under three simultaneous forks one child was parked as `paused` and the SDK wait timed out after 120 s. Own wait loop that
  resumes parked children, parallel fork creation, same wait for the parent's resume.
- Errors on the way: platform names are limited to 22 characters; a `429 concurrent quota reached (5 / 5)` after crashed runs left forks behind
  (forks get random names, so `gc` never matched them): `gc` now removes forks of ours, plus `gc --all`.
- Live result: three forks, three probes in parallel, only `NODE_ENV=production` produced proof; 38 s for the race, 48 s total, nothing leaked.

## 14:10-14:40 | memory, static layer, Gemini
- Threat memory (SQLite: scan cache, indicators, skills) and skill learning. The first learner crashed on a malformed model-written value, so lure
  settings now come only from the probe that produced proof. Sibling-fixture test: the skill was used but did **not** speed up the scan.
- capa v10 standalone inside a 2 GB sandbox: 3.9 s, 220 MB, 12-13 capability findings with ATT&CK ids on a compiled C fixture; gcc compiles it
  inside the sandbox. Scan of the binary: 50 s, malicious with proof.
- Gemini 3.x needs the `thought_signature` echoed on multi-turn tool calls (HTTP 400 otherwise; LangChain drops it): an httpx transport
  re-injects it and refreshes the gcloud token. `gemini-4-argon` blocks security prompts: not used.
- Deep research first hallucinated (wrong year and vendor) because the scraping search failed; replaced by Google Search grounding, and briefs
  without a source URL are withheld.

## 14:40-15:20 | distribution and Stripe Projects depth
- HTTP API with Server-Sent Events, an MCP server (verified with a real MCP client over stdio), report hosting from a sandbox with ingress
  (public URL returned 200), `sandtrap doctor`, LangGraph checkpoints in the Neon Postgres provisioned by Stripe Projects, Langfuse tracing.
- npm targets (lifecycle scripts run under the lure) and C targets.
- AgentMail provisioned through Stripe Projects: the agent's own inbox. Live round trip: a second inbox emailed `fixture:gated-stealer`, the agent
  scanned it in sandboxes and replied with the verdict, ATT&CK ids, evasion evidence, remediation and a public report link.
- Final benchmark: 12 fixtures, Sandtrap 10/10 malicious detected against 4/10 for the plain sandbox, both clean fixtures clean, a real PyPI
  package clean. One transient failure in a full run (passed when re-run alone); the benchmark script now retries once.

## 15:25-16:10 | use cases, incidents and the gaps they exposed
- Researched real supply-chain incidents (event-stream, XZ, SUNBURST, Codecov, ua-parser-js, ctx, tj-actions, Shai-Hulud, Nx, dependency confusion,
  slopsquatting) and verified each fact against its source before writing it down (`docs/USE-CASES.md`). Two claims could not be verified (the XZ
  trigger conditions on the first search, and a "pulled within hours" statement about ua-parser-js): the first was confirmed from the original
  oss-security post, the second was removed.
- Matching the incidents to the product exposed real gaps: Codecov and `ctx` stole environment variables, but our canaries were files and the sink
  decoded base64 only as a whole body. Added canary environment variables, embedded-base64 decoding (with tests), the `env-b64-exfil` fixture and a
  `script:` target with the `script-ci-uploader` fixture (a tampered CI uploader). Both are proven in 33-38 s.
- Bugs on the way: the platform rejects environment keys not declared at sandbox creation (export inside the script instead), and the tracing helper hid
  the real exception behind a generator error (fixed).
- Full benchmark re-run: **14 fixtures, 12 malicious: Sandtrap 12/12, plain-sandbox view 4/12**, both clean fixtures clean, no regressions.

## Verified and not verified
- Verified: 78 unit tests; `doctor` all OK; API and SSE live; MCP live; email live; public report live; Langfuse traces visible in the Langfuse
  dashboard (confirmed by the author).
- Not verified or not built: HTTPS body interception, the DeBERTa injection classifier, Grafana, a decompiler, Docker-in-sandbox execution.

## 2026-10-18: real-software run, fixes, video assets
- Ran `scripts/real_world.py` (6 packages, 2 installers): first result had three false "malicious" verdicts and two "inconclusive"; see decision 18.
- Added tests for the scorer cases and for malformed tool arguments (87 tests pass); re-ran the 14-fixture benchmark (12/12 vs 4/12; one
  fixture needed a rerun after the model sent a malformed tool argument, now handled).
- The CLI no longer prints structured logs to the terminal (they still go to `logs/`).
- Built `scripts/make_clips.py` (silent B-roll from real outputs) and `docs/VIDEO-TIMELINE.md`.
