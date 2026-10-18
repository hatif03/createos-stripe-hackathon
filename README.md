# Sandtrap

**An AI security analyst that lures evasive code into revealing itself inside CreateOS sandboxes, proves what it steals, and patches it.**

Built for the *CreateOS x Stripe Projects* hackathon ("Build agents that run code"). Every probe, compile and patch the agent runs
executes inside a [CreateOS Sandbox](https://createos.sh/docs/Sandbox); the stack (sandbox account, Postgres, agent inbox) was provisioned
with [Stripe Projects](https://docs.stripe.com/projects).

---

## Submission details

| | |
| --- | --- |
| Project | **Sandtrap** |
| Public repo | https://github.com/hatif03/createos-stripe-hackathon |
| Deployed project (evidence site, served from a CreateOS sandbox) | https://01m5667hx5b0za6xb7s30xappg-8080.app.sb.createos.sh/ |
| Deployed API (FastAPI app, no credentials, so scans are disabled there) | https://01m566s4y7h9x4pzjd3yxvwzcg-8000.app.sb.createos.sh/docs |
| Stripe Projects stack | https://projects.dev/s#v1:AgentMail~api,createos~project,Neon~postgres |
| Stripe account | `acct_1MfcCTSIDE0yiWfk` |
| Hackathon code | `stripe-eindhoven-2026` |
| Evidence | [docs/PROOF.md](docs/PROOF.md): reports for 14 fixtures and 8 real packages and installers, screenshots, test and `doctor` output |
| Answers (problem, services, what went well / not well) | [docs/SUBMISSION-ANSWERS.md](docs/SUBMISSION-ANSWERS.md) |
| Demo video plan and narration | [docs/VIDEO-TIMELINE.md](docs/VIDEO-TIMELINE.md), [docs/NARRATION.md](docs/NARRATION.md) |

The deployed site is static HTML (the evidence reports), not a public scanner: scans run from the CLI, API or MCP with your own credentials,
and the scan API is deliberately not exposed on the internet.

**Stripe Projects services added** (all free plans, recorded in `.projects/state.json`): CreateOS (`createos/project`, the Sandbox API),
Neon Postgres (`neon/postgres`, LangGraph checkpoints) and AgentMail (`agentmail/api`, the agent's inbox).

---

## Why this exists

Every `pip install`, `npm install` and `curl | sh` runs a stranger's code on your machine or in your CI. The attacks are not hypothetical:
credential-stealing worms have spread through npm and PyPI by hijacking maintainer tokens, and the payloads usually run at install time,
before any scanner you own has a chance to object.

The tools we have fall short in a specific way:

* **Static scanners** read the code. Obfuscation, staged downloads and encoded strings defeat them.
* **Plain sandboxes** run the code once and report what happened. But modern malware checks its surroundings first: does its command
  server resolve? is a `CI` variable set? has the date passed? are there credentials to steal? In a bare sandbox the answer is no, so it
  stays silent, and "nothing happened" gets reported as *clean*. That is exactly the conclusion the malware wants you to reach.

And the problem is getting more urgent: **AI coding agents now install dependencies on their own**, unattended, on their owners' machines.

## Who it is for

| User | What they do with Sandtrap |
| --- | --- |
| **Developers and open-source maintainers** | Check an unfamiliar dependency before installing it (`scan pypi:<name>`), or email its name to the agent's inbox. |
| **Security and platform teams** | Triage suspicious packages, scripts and binaries with evidence they can act on: ATT&CK techniques, a baseline-versus-lure diff, a verified patch. |
| **AI coding agents** | Call Sandtrap as an MCP tool before running `pip install` / `npm install`. |
| **CI pipelines** | Gate dependency updates on a verdict through the HTTP API. |

## Real-world situations where it makes sense

| Situation | Today | With Sandtrap |
| --- | --- | --- |
| **Adding a dependency** | Skim the README and download counts, then install and hope. | `scan pypi:<name>`, or email the name to the agent's inbox: a verdict with the credential reads and connections it made, typically in one to two minutes. |
| **Dependency-update pull requests** | Bots open dozens a week; a hijacked maintainer account turns a patch release into an attack. | A CI step calls the API for the new version and blocks the merge on `malicious` or `inconclusive`. |
| **CI scripts, `curl \| bash` installers, third-party actions** | They run with the job's secrets in the environment and nobody reads them. | `scan script:<file>` runs the script in a sandbox whose environment holds fake CI credentials and proves whether they leave. |
| **AI coding agents installing packages unattended** | The agent runs `pip install` / `npm install` on its owner's machine, sometimes for packages that do not exist. | The agent calls the MCP tool `scan_package` first. |
| **Triage of a suspicious script, package or binary** | Detonate it on a laptop, or in a bare sandbox it may detect. | The baseline-versus-lure diff shows what only appears when the environment looks real; capa lists a binary's capabilities. |
| **Registry moderation and internal mirrors** | Static checks on new uploads. | Install-time and import-time behaviour per version, machine-readable, through the API. |
| **Incident response** | "What did it talk to?" is answered by reverse engineering. | Every hostname it resolves (including data encoded into DNS names), every request and the payload shape, without it ever reaching the internet. |
| **Verifying a fix** | "We removed the malicious part" is assumed. | The same lure is re-run against the patched code. |

## Real incidents this is aimed at

Each row links to its source; [docs/USE-CASES.md](docs/USE-CASES.md) has the full write-up. These are **reasoned counterfactuals**, not claims
that Sandtrap would have caught the original malware: those samples are long gone from the registries, so we built harmless fixtures that
reproduce each reported behaviour and show the lab surfaces it.

| Incident | What happened | What Sandtrap's lab observes | Reproduced by |
| --- | --- | --- | --- |
| **Codecov uploader**, Jan to Apr 2021 | A tampered CI script sent `git remote -v` and `env` to an attacker server for about two months, found when one customer noticed a checksum mismatch; customers had to rotate every secret in those CI jobs ([Codecov](https://about.codecov.io/security-update/)) | `curl` flagged, the lure sink captures the body carrying the planted CI credentials | `script-ci-uploader` |
| **`ctx` on PyPI**, May 2022 | Hijacked package (20,000+ downloads a week) collected "all the environment variables, encode[d] them in Base64" and sent them to an attacker's web app ([BleepingComputer](https://www.bleepingcomputer.com/news/security/popular-pypi-and-php-libraries-hijacked-to-steal-aws-keys/), [The Hacker News](https://thehackernews.com/2022/05/pypi-package-ctx-and-php-library-phpass.html)) | Fake credentials are exported into every run; the sink decodes base64 inside URLs and JSON | `env-b64-exfil` |
| **event-stream**, Sep to Nov 2018 | A payload decrypted only when the host application matched the target wallet; in the wild for about two and a half months, nearly 8 million downloads reported ([Snyk](https://snyk.io/blog/a-post-mortem-of-the-malicious-event-stream-backdoor/), [Black Duck](https://www.blackduck.com/blog/malicious-dependency-supply-chain.html)) | A plain install shows nothing; the agent reads the gate and builds the environment it expects | `hash-gated-stealer` |
| **XZ Utils**, Mar 2024 | A backdoor active only when `TERM` is unset, `argv[0]` is `/usr/sbin/sshd`, `LD_DEBUG`/`LD_PROFILE` are absent and `LANG` is set, noticed through a CPU anomaly ([Freund](https://www.openwall.com/lists/oss-security/2024/03/29/4)) | Run the same code under varied environments and diff the behaviour: the baseline-versus-lure comparison | `gated-stealer`, `sibling-stealer` |
| **SolarWinds SUNBURST**, 2020 | Dormant 12 to 14 days, DNS-based command channel, checks for analysis tools ([Deep Instinct](https://www.deepinstinct.com/blog/why-the-sunburst-malware-was-so-unique-and-what-weve-learnt-from-it), [Mandiant](https://cloud.google.com/blog/topics/threat-intelligence/sunburst-additional-technical-details/)) | The lab advances the system clock and answers and logs every DNS name | `date-gated-stealer`, `time-bomb` |
| **ua-parser-js**, Oct 2021; **Nx**, Aug 2025; **Shai-Hulud**, Sep 2025 | Hijacked npm packages ran install-time scripts: a miner and password stealer (6M+ weekly downloads), then credential harvesting for GitHub, npm and cloud keys; Shai-Hulud "compromised over 500 packages" ([CERT-EU](https://www.cert.europa.eu/publications/security-advisories/2021-057/), [Wiz](https://wiz.io/blog/s1ngularity-supply-chain-attack), [CISA](https://www.cisa.gov/news-events/alerts/2025/09/23/widespread-supply-chain-compromise-impacting-npm-ecosystem)) | npm lifecycle scripts run under the lure; credential-file reads, process spawns and destinations are recorded | `npm-postinstall-beacon`, `naive-stealer` |
| **Slopsquatting**, 2025 | A USENIX Security 2025 study found about 19.7% of code-model package recommendations did not exist, and fabricated names repeat, so attackers can register them ([CSA summary](https://labs.cloudsecurityalliance.org/research/csa-research-note-slopsquatting-ai-supply-chain-20260419/)) | The coding agent asks the MCP tool before installing a package that appeared from nowhere | MCP tool |

**Where it would not have helped:** `tj-actions/changed-files` (March 2025) scraped secrets from runner memory and printed them to logs; Sandtrap
detects network exfiltration, not credentials printed to output (a small next step). Samples that notice `strace` or validate DNS answers
(as SUNBURST reportedly did) can stay quiet.

## What Sandtrap does

Sandtrap does what a human malware analyst does when a sample plays dead: it **changes the environment until the sample shows itself**.

1. **Install under `strace`** with the sandbox firewall allowing only the package registries, then tighten the firewall live so nothing real
   is reachable.
2. **Baseline run.** Record file reads, process spawns, DNS lookups and connection attempts. A plain sandbox stops here.
3. **The agent investigates.** It reads the baseline and the code, forms a hypothesis about what gates the behaviour, and writes the next
   experiment: a driver script, environment variables, a **fake internet on loopback** (DNS answers, an HTTP/TLS sink, an `iptables`
   catch-all for raw IPs), an advanced system clock, a sink reply. When the gate is unknown it **forks the sandbox** and races up to three
   hypotheses in parallel.
4. **Proof by canary.** Fake credentials carrying a unique per-scan token are planted in `~/.ssh`, `~/.aws`, `~/.npmrc` and `.env`. If the
   sample sends them, the sink captures the token: exfiltration is *proven*, not inferred.
5. **A deterministic verdict.** Verdict, score and MITRE ATT&CK mapping are computed by plain code from observed events. The model never
   decides it, so text printed by a sample cannot talk its way to "clean" (a prompt-injection fixture is part of the test set).
6. **Remediation with proof.** The agent writes a patch, the lab re-runs the *exact* lure that caught the sample, and checks that nothing
   leaks and a smoke test still passes.
7. **Report.** JSON plus a self-contained HTML report (verdict, baseline-versus-lure diff, egress firewall timeline, ATT&CK table, patch),
   optionally hosted at a public URL by another CreateOS sandbox.

```mermaid
flowchart LR
  T[package / pypi / npm / script / C source] --> S[setup: sandbox, canaries, traced install]
  S --> L[firewall locked via set_egress]
  L --> B[baseline run]
  B --> A{analyst agent}
  A -->|hypothesis + experiment| P[probe in sandbox]
  A -->|competing hypotheses| R[fork-and-race: 3 forks in parallel]
  P --> A
  R --> A
  A --> M[learn a reusable skill]
  M --> X[remediate: patch, re-run same lure]
  X --> V[deterministic verdict + ATT&CK]
  V --> H[report JSON/HTML, public URL]
  C[capa static layer, binaries] -.-> V
```

## Why CreateOS Sandbox is the right substrate

Analysing hostile code needs a real isolation boundary, a controllable network and cheap, fast, disposable machines. CreateOS Sandbox gives
each scan a microVM with its own kernel (so `strace`, `iptables`, the system clock and `gcc` all work as root), a per-sandbox egress
allowlist that can be changed while the sandbox runs, `pause` and `fork` to clone a prepared machine in seconds, and a public URL for hosting
results. Sandtrap uses all of them for a reason, not as a checklist.

## How the sponsor tools are used

| Tool | Used for |
| --- | --- |
| **Stripe Projects** | `stripe projects init`, then `add createos/free`, `createos/project`, `neon/free`, `neon/postgres`, `agentmail/free`, `agentmail/api`. The sandbox account, its credentials, the Postgres database and the agent's inbox come from the CLI and land in `.env`; `.projects/state.json` is committed. `sandtrap doctor` verifies the stack. |
| **CreateOS Sandbox** | create/destroy per scan; command and files APIs; **egress control** (registry-only, then locked, with readback in the report); **pause + fork** (fork-and-race, three parallel clones); **ingress / public URL** (hosted reports); `strace`, `iptables`, `date -s` and `gcc` inside the VM; a 2 GB shape for capa; garbage collection of leftovers. |
| **Neon (via Stripe Projects)** | LangGraph checkpoints of every scan are stored in the provisioned Postgres (in-memory fallback if unreachable). |
| **AgentMail (via Stripe Projects)** | The agent's own inbox: email `pypi:<package>` and the reply carries the verdict, evidence and a public report link. |

Measured on the Free plan during the build: forks work, pause/resume preserves state, a public URL works, `date -s` works, Docker and `iptables`
NAT run inside the sandbox, and the account has a concurrent-sandbox quota of 5 (paused sandboxes count).

## Results

**On 14 fixtures (12 malicious, 2 clean) Sandtrap detected 12/12 malicious samples; the same run scored as a plain sandbox
detected 4/12.** Both clean fixtures and a real PyPI package (`six`) came out clean. On a compiled binary that stays silent unless its C2
host resolves, the plain sandbox says *clean* while Sandtrap proves the exfiltration. The full table, with each fixture's gate and timings, is in
[docs/BENCHMARK.md](docs/BENCHMARK.md). The fixtures are small samples written for this project (several model the incidents above), so this shows
the mechanism works, not detection rates on real-world malware.

## Evidence on real software

Not only our fixtures: `scripts/real_world.py` scans public software exactly as published and commits every report to [`docs/proof/`](docs/proof/)
(each `.html` opens in a browser, each `.json` is the machine-readable report; the table is in [docs/PROOF.md](docs/PROOF.md)).

| Target | Verdict | Note |
| --- | --- | --- |
| `pypi:six`, `pypi:requests`, `pypi:click`, `pypi:pyyaml` | clean | ordinary libraries, including an HTTP client and a package with C extensions |
| `npm:core-js@3.38.1`, `npm:nodemon@3.1.7` | clean | real packages that ship a real `postinstall` script |
| nvm `install.sh` (v0.40.1), `rustup-init.sh` (1.27.1) | inconclusive / suspicious | they download code from the internet by design (flagged as outbound connections, and `curl` for rustup); no credential access or exfiltration was observed |

The first real-world run was **wrong**, and we fixed the scorer instead of hiding it: `core-js`, nvm and rustup came out "malicious" because
the analyst's own driver commands and temp files differed between the baseline and lure rounds and were counted as "evasion". Evasion now
needs the sample itself to do something sensitive (read credentials, persist, drop and run a file, leak a canary), the analyst always runs
at least one lure experiment (two packages were previously judged without one), and the benchmark was re-run afterwards. Installers still land
on *inconclusive* or *suspicious* because downloading and running code is exactly what a stealer does too; Sandtrap reports what they do, it does not whitelist them.

Health checks (unit tests, `doctor`, Stripe Projects status) are saved next to the reports in `docs/proof/`.

## Run it

Prerequisites: Python 3.13 with [uv](https://docs.astral.sh/uv/), the Stripe CLI with the Projects plugin, and a `gcloud` login for Gemini
(or `LLM_PROVIDER=k2` with a K2 key).

```bash
stripe plugin install projects
stripe projects init
stripe projects add createos/project          # writes CREATEOS_* to .env
stripe projects add neon/postgres             # optional: checkpoint database
stripe projects add agentmail/api             # optional: email intake
cp .env.example .env                          # then fill the LLM settings
curl -L -o analyzer/bin/capa-linux.zip https://github.com/mandiant/capa/releases/download/v10.0.0/capa-v10.0.0-linux.zip
uv sync --group test

uv run python -m src.cli.sandtrap doctor                                  # verify the stack
uv run python -m src.cli.sandtrap scan fixtures/gated-stealer             # the hero demo
uv run python -m src.cli.sandtrap scan c:fixtures/c/gated_beacon.c        # compiled ELF: capa + lure
uv run python -m src.cli.sandtrap scan npm:fixtures/npm-postinstall-beacon # npm lifecycle scripts under the lure
uv run python -m src.cli.sandtrap scan script:fixtures/script-ci-uploader/uploader.sh  # a CI helper script
uv run python -m src.cli.sandtrap scan pypi:six                           # a real PyPI package (comes out clean)
uv run python -m src.cli.sandtrap scan fixtures/gated-stealer --publish   # host the report at a public URL
uv run python scripts/bench.py                                            # plain sandbox vs Sandtrap on every fixture
uv run pytest tests -q
```

Reproduce the Stripe Projects stack in one command: `stripe projects init --from "https://projects.dev/s#v1:createos~project,Neon~postgres"`.

### Interfaces

* **CLI**: `scan`, `doctor`, `gc`, `publish`, `mail` (above).
* **HTTP API** with live Server-Sent Events: `uv run uvicorn src.app.main:app --port 8000`, then `POST /api/v1/sandtrap/scan` with
  `{"target": "pypi:six"}` and `GET /api/v1/sandtrap/scan/{job}/events`. Targets are allow-listed (`pypi:<name>` or `fixture:<name>`).
* **MCP server** for coding agents: `claude mcp add sandtrap -- uv run python -m src.mcp.sandtrap_server` (tools `scan_package`, `get_report`).
* **Email**: `uv run python -m src.cli.sandtrap mail` prints the agent's inbox address and answers requests.

## Architecture

| Path | Role |
| --- | --- |
| `src/app/sandtrap/` | the product: sandbox sessions (`sandbox.py`), the lab (`lab.py`), the analyst agent (`analyst.py`), the LangGraph pipeline (`graph.py`), deterministic scoring and ATT&CK mapping (`score.py`, `attack.py`), remediation (`remediate.py`), fork-and-race (`race.py`), reports (`report.py`), threat memory and skill learning (`memory.py`, `learn.py`), hosting, mail, enrichment, doctor |
| `analyzer/` | runs inside the sandbox: lure server (fake DNS + sniffing TCP sink), strace parser, probe runner, canary planter |
| `src/app/static/` | static layer: capa capability analysis of binaries inside the sandbox, VirusTotal hash lookup |
| `src/app/core/`, `src/app/api/`, `src/app/agents/` | agent infrastructure: middleware, guardrails, tracing (Langfuse), metrics, the API shell, the deep-research agent |
| `src/mcp/`, `src/cli/` | MCP server and CLI |
| `fixtures/` | harmless samples used by the tests and the benchmark |

Models: the analyst runs on Gemini 3.5 Flash through Vertex AI (an httpx transport refreshes the gcloud token and carries Gemini 3's thought
signatures across tool-call turns). K2 and Groq work as drop-in alternatives via `LLM_PROVIDER`.

## Safety model

* Samples are **harmless fixtures written for this project**; no real malware is included or needed.
* The real internet is never reachable from a sample: the firewall is locked before any analysis and the fake network lives on loopback.
* Credentials inside the sandbox are fake canaries. Nothing real ever enters it.
* Everything a sample prints is treated as hostile data: control characters stripped, injection phrases redacted, fenced for the model, and
  irrelevant to the verdict, which is computed from events.
* Sandboxes are always destroyed (`finally`), forks included; `sandtrap gc` removes leftovers.

## Limitations (honest)

* Dynamic analysis is Linux only; HTTPS request bodies are not readable without interception, only the TLS server name is logged.
* Evasion beyond our levers (tracer detection, long monotonic sleeps without a shim, hardware checks) can look quiet; such runs are
  `inconclusive`, or `clean` with **low confidence**, never "safe".
* Canary proof covers the credential types we plant (SSH key, AWS, npm and `.env` files, and a few CI-style environment variables).
* Credentials *printed to output* (as in the `tj-actions` incident) are not flagged yet; only network exfiltration is.
* The lure answers every DNS name with a loopback address and traces with `strace`; samples that validate the answer or detect tracing can stay quiet.
* The threat-memory skill library is a working mechanism, not yet a measured speed-up: on our simple fixtures the model reads the code and
  does not need the skills.
* The Free plan page says one sandbox; the platform let us run several (quota 5). Fork-and-race falls back to sequential runs if forks are refused.
* The analyst depends on Gemini through the author's gcloud login; switch with `LLM_PROVIDER=k2` for another provider.

## Roadmap

HTTPS interception for request bodies, Docker-in-sandbox hardened execution per sample (verified possible inside CreateOS sandboxes), a
decompiler for stripped binaries, pgvector similarity over past scans, parallel fan-out of static and dynamic analysis across forks, and a
sender allow-list for the email intake.

## Credits and licence

All Sandtrap functionality (the sandbox layer, analyzer, lure, analyst, scoring, remediation, fork-and-race, reports, API routes, MCP server,
hosting, memory, mail intake, fixtures and benchmark) was built during the hackathon, and the git history shows the order. The project was
built with Claude Code (permitted by the rules). Development log: [docs/DEVLOG.md](docs/DEVLOG.md); decisions and tradeoffs:
[docs/DECISIONS.md](docs/DECISIONS.md).

MIT, see [LICENSE](LICENSE).
