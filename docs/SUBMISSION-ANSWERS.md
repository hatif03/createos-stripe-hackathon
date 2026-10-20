# Hackathon submission answers

**Project:** Sandtrap. **One line:** an AI analyst that lures evasive code into revealing itself inside CreateOS sandboxes, proves exfiltration with
canary credentials, and patches it.

## What problem does it solve, and for whom?

Installing a package or running a script means running a stranger's code, and the attacks that matter (Codecov's tampered uploader, the `ctx`
package on PyPI, event-stream, the XZ backdoor) were built to behave only in the right environment: a CI variable set, a hostname that resolves,
a date that has passed. A normal sandbox runs the code once, sees nothing, and calls it clean. Sandtrap plays the analyst instead: it notices a
sample playing dead, reads its code, forms a hypothesis about the gate, and changes the environment (fake DNS, a fake clock, a loopback internet,
CI-style fake credentials) until it shows itself. It proves theft with per-scan canary credentials, computes the verdict from observed events in
code (never from the model), and then patches the package and re-runs the same attack to check the fix. It is for developers adding
dependencies, teams that run dependency-update bots and CI scripts, people who let AI coding agents install packages unattended (it has an MCP
tool for that), and registry or security teams doing triage. On our 14 fixtures it detects 12/12 malicious samples where a plain sandbox view
detects 4/12; on real packages and installers, results are in `docs/PROOF.md`.

## Which services did you add with Stripe Projects?

Three, all on free plans, provisioned with `stripe projects add` and recorded in `.projects/state.json` (status output in
`docs/proof/stripe-projects-status.txt`):

- **CreateOS** (`createos/free` plan, `createos/project`): the Sandbox API. Every install, probe, compile and patch runs in a Firecracker sandbox;
  we use egress control, pause/fork (fork-and-race), ingress (hosted reports) and garbage collection.
- **Neon Postgres** (`neon/free`, `neon/postgres`): the LangGraph checkpoint store for the agent's runs.
- **AgentMail** (`agentmail/free`, `agentmail/api`): the agent's inbox; email a package name and get a verdict back.

## What went well / not well

**Went well.** Stripe Projects gave us a sandbox account, a database and an inbox with synced credentials in minutes, and `sandtrap doctor` checks all
of them. CreateOS did what the idea needed: a real VM with `strace`, `iptables` and `date -s`, live egress changes, and fork/pause/ingress all
worked on the Free plan. Keeping the verdict in code (the model only forms hypotheses) made the system testable: a prompt-injection fixture cannot
flip a result, and there are 88 unit tests. Working from real incidents exposed real gaps (environment-variable canaries, base64 inside URLs,
script targets) that we then built and proved.

**Not well.** Our first run on real software was wrong: `core-js`, nvm and rustup came out "malicious" because the analyst's own commands were
counted as evasion, and two packages were judged without any lure test. We fixed the scorer and the loop, re-ran the benchmark, and wrote it up
in `docs/DECISIONS.md` (18). An intermittent crash (`'list' object has no attribute 'get'`) turned out, days later, to be our Gemini transport shim choking on Vertex 429
errors, which arrive as a JSON array; fixed with a test, and 429s are now retried. Other friction: Gemini 3.x needs `thought_signature` echoed back on tool calls,
which LangChain drops (we wrote a transport shim); the first research agent hallucinated when its search failed, so it now refuses to answer
without sources; the Free plan allows five concurrent sandboxes (paused ones count) although the page suggests one, and forks can be parked
paused; environment keys must be declared at sandbox creation. Limits we state openly: HTTPS bodies are unreadable, samples that detect `strace`
or validate DNS answers can stay quiet, installers that download code stay "suspicious", the benchmark uses harmless fixtures rather than live
malware, and the skill memory is a mechanism with no measured speed-up.
