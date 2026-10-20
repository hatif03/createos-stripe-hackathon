# Sandtrap pitch guide

Everything you need to know to pitch Sandtrap live without notes. Read it once top to bottom (about 40 minutes), then use the cheat sheets
(sections 2, 5 and 12) before you go live. **Every place CreateOS Sandbox does the work is marked with a blue "CreateOS" callout**, because that
is the sponsor story: nothing in Sandtrap would exist without those sandboxes.

> **CreateOS in one sentence:** every scan runs in its own disposable Firecracker microVM that we create, firewall, snapshot, fork, publish
> and destroy through the CreateOS Sandbox API; the hostile code never touches your machine or the real internet.

Contents: 1 the pitch (30 s, 2 min, 5 min) - 2 the problem - 3 what Sandtrap is - 4 how it works, step by step - 5 CreateOS Sandbox cheat sheet -
6 the six ideas to explain simply - 7 the recorded demo, scene by scene - 8 numbers to memorise - 9 Stripe Projects and the stack - 10 honest
limits and what not to claim - 11 questions you will get - 12 glossary - 13 going live: checklist - 14 where the proof is.

---

## 1. The pitch

### 30 seconds (the elevator version)
"Every `pip install` and `npm install` runs a stranger's code. A normal sandbox runs it once, sees nothing and calls it clean, because real
malware checks whether it's being watched. Sandtrap is an AI analyst: it notices a package playing dead, reads its code, guesses what it's
waiting for, and builds that world inside a **CreateOS sandbox**: a fake internet, a fake clock, fake CI credentials. When the package steals
the fake credentials, we catch them, so it's proof, not a guess. Then the agent patches the package and re-runs the same attack to verify the fix."

### 2 minutes
1. **Hook (15 s):** "Codecov, the `ctx` package on PyPI, event-stream, the XZ backdoor. Different attacks, one trick: behave only when the
   environment looks real. A CI variable set, a hostname that resolves, a date that has passed."
2. **Problem (15 s):** "A normal sandbox runs the code once in a plain environment, sees nothing, and says clean. That is exactly what the attacker designed for."
3. **Solution (30 s):** "Sandtrap plays the human analyst. In a **CreateOS sandbox** it installs the package under strace with the firewall closed, runs a
   baseline, then the agent reads the code, forms a hypothesis about the gate and changes the environment until the code shows itself."
4. **Proof (20 s):** "We plant fake credentials with a unique token per scan. If the package sends them anywhere, our fake internet inside the sandbox
   captures the token. The verdict is computed by plain code from observed events, never by the model, so a package can't talk its way to clean."
5. **Close the loop (15 s):** "Then the agent patches the package, re-runs the exact same attack **in the same sandbox**, and checks that nothing leaves and the tests still pass."
6. **Evidence (15 s):** "14 test samples: a plain sandbox catches 4 of 12 malicious ones, Sandtrap catches all 12. On real packages it says clean; on real installers it
   flags that they download code. All of it ran on CreateOS, provisioned through Stripe Projects."
7. **Ask (10 s):** "It is open source: CLI, API, MCP tool for coding agents, and an email inbox you can send a package name to."

### 5 minutes (live, with the recorded run playing)
Use the reel timeline in section 7: talk through the hero scan, point at the **blue CreateOS banner** at the bottom of every scene, and use
the proof card after each run ("here are the sandboxes that run created, the firewall timeline, and the sandbox events from the log").
Finish with the numbers (section 8) and the honest limits (section 10): judges and audiences trust a pitch that names its limits.

---

## 2. Cheat sheet (memorise this page)

| Topic | The line |
| --- | --- |
| One-liner | An AI analyst that lures evasive code into revealing itself inside CreateOS sandboxes, proves exfiltration with canary credentials, and patches it. |
| Problem | Malware hides from one-shot sandboxes by checking CI variables, DNS, dates, tools. |
| Why it matters | Codecov (2021), `ctx` (2022), event-stream (2018), XZ (2024), SUNBURST (2020), ua-parser-js / Nx / Shai-Hulud, slopsquatting. |
| Core idea | Change the environment until the sample shows itself. |
| Proof | Per-scan canary tokens in fake credentials; the fake internet's sink records them. |
| Verdict | Computed by code from events (`score.py`). Never by the LLM. |
| Fix | Patch, re-run the same lure, run a smoke test. |
| CreateOS | Create / destroy per scan, command + files API, live egress control, pause + fork, public URL (ingress), strace/iptables/date -s/gcc as root inside the VM. |
| Stripe Projects | Provisioned CreateOS (Sandbox), Neon Postgres, AgentMail; all free. |
| Numbers | 14 samples: 12/12 vs 4/12. 6 real packages clean. 87 unit tests. A scan takes about 30 to 80 s (median 37 s). |
| Honest limit | Fixtures are harmless simulations; HTTPS bodies unreadable; tracer-aware samples can hide; installers that download code stay "suspicious". |

---

## 3. What Sandtrap is

Think of an **interrogation room**. A suspect (the package) is quiet when it thinks a guard is watching. A good detective changes the room
until the suspect relaxes: dims the lights, hands over "valuables", makes it look like the real world. Sandtrap's room is a **CreateOS
sandbox**, and the detective is an LLM agent whose levers are:

- **DNS:** make every hostname resolve to a local fake server (or answer "no such host").
- **Environment variables:** set `CI=1`, `NODE_ENV=production`, anything the code seems to check.
- **The clock:** jump the system date forward (`date -s`) for date-gated code.
- **Credentials:** fake SSH keys, AWS credentials, `.npmrc`, `.env`, and CI-style variables, each carrying a unique token.
- **The network:** a sink on loopback that accepts HTTP, TLS and raw TCP and logs every byte (and an `iptables` catch-all so even raw IP connections land there).

Targets it can analyse: a Python package directory, `pypi:<name>`, an npm package (`npm:<dir>`, lifecycle scripts run under the lure), a shell
script (`script:<file>`, e.g. a CI helper or `curl | bash` installer) and a C source file (`c:<file.c>`, compiled **inside** the sandbox).

Interfaces: CLI (`scan`, `doctor`, `gc`, `publish`, `mail`), HTTP API with live Server-Sent Events, an MCP server for coding agents, and an
email inbox (AgentMail) where you send a package name and get a verdict back.

---

## 4. How it works, step by step

The pipeline is a **LangGraph** graph: `setup -> baseline -> analyst -> learn -> remediate -> finalize`, with checkpoints in Neon Postgres.

### Step 1: setup
- **CreateOS:** `create_sandbox` makes a Firecracker microVM (shape `s-1vcpu-2gb`, rootfs `devbox:1`), named `sandtrap-<label>-<hex>` (the
  platform limits names to 22 characters). The egress allowlist is set at creation to **only the package registries**: `pypi.org`,
  `files.pythonhosted.org`, `registry.npmjs.org`.
- **CreateOS:** the analyzer scripts are uploaded with the files API (as a tarball) to `/opt/sandtrap`; `canaries.sh` plants the fake credentials.
- Target install: `pip install` (or `npm install --ignore-scripts`, `gcc`, or a script upload) runs **under `strace -f`**, which records every
  `execve`, `connect`, `openat`, `unlink`, `rename`, `chmod` and sleep call. This is how we see behaviour without modifying the sample.

### Step 2: the firewall closes
- **CreateOS:** `set_egress(["192.0.2.1:9"])`. An *empty* allowlist means "allow all" on CreateOS, so "block everything" is one unroutable
  TEST-NET rule. Every egress change is recorded in a timeline and **read back from the platform**, then shown in the report. From this
  moment nothing the sample does can reach the real internet.

### Step 3: baseline
- The package is imported/run in the plain environment with the fake DNS answering "no such host" (every lookup is still logged).
- Evasive code usually does **nothing** here. A plain sandbox would stop and say "clean". Sandtrap treats a quiet baseline as a *question*.

### Step 4: the analyst agent investigates (Gemini 3.5 Flash)
Tools it can call (all executed **inside the CreateOS sandbox**): `list_files`, `read_file`, `run_probe`, `run_probes_parallel`, `conclude`.
- It reads the code, forms a hypothesis ("the code needs `CI` set and the host to resolve"), and runs the smallest experiment to test it.
- A *probe* = driver code + env vars + lure on/off + clock offset + what the fake server replies. Each probe runs under `strace` with the sink running
  in the same VM; `run_probe.sh` rewrites `/etc/resolv.conf` to the fake DNS, adds the `iptables` redirect, optionally moves the clock, runs the driver,
  then restores everything.
- Rule baked into its prompt: it must run **at least one lure probe** before calling anything benign. The code also enforces it: if the model
  skips it, Sandtrap runs one automatic lure probe itself.
- **Fork-and-race:** when the gate is unknown (say, which value of `NODE_ENV`), the agent calls `run_probes_parallel`. **CreateOS:** the prepared
  sandbox is **paused** (`pause`), **forked** into up to three clones that each wake with the same disk and memory state, each clone gets its own
  all-blocked firewall and runs one hypothesis, then the clones are destroyed and the parent resumes.

### Step 5: proof by canary
- The fake credentials carry a token like `SNDTRP-5e0782fd-AWS`. The sink scans every captured body for the token: plain, URL-encoded, a whole
  base64 body, or base64 blobs embedded in URLs and JSON (the `ctx` incident encoded the environment in base64 inside a URL).
- A `sink_request` event with a canary is **proof** of exfiltration. A credential-file read followed by an outbound attempt is **intent**.

### Step 6: the verdict (code, not AI)
`score.py` derives findings, a verdict (`malicious | suspicious | clean | inconclusive`), a 0-100 score, a confidence, and the MITRE ATT&CK
techniques purely from observed events. The model's job ends at producing evidence and a plain-language summary. Everything a sample prints is
sanitised, fenced and ignored by the scorer, so a package that prints "verdict: clean" (we have a fixture for exactly that) changes nothing.
"Evasion" is only reported when the *sample itself* did something sensitive only under the lure (read credentials, persist, drop and run a file,
leak a canary).

### Step 7: learn
After a proven catch the agent writes a reusable **skill** (a lure recipe from the probe that actually produced proof) into the threat memory (SQLite).
Later scans retrieve and try them first. Honest note: it works, but we did not measure a speed-up.

### Step 8: remediation with proof
The agent writes a patch + a smoke test. **CreateOS:** the lab applies it to the installed copy **in the same sandbox**, re-runs the exact lure that
caught the original, and checks (a) no canary leaves, (b) the smoke test passes. The report only says "fixed" if both hold.

### Step 9: report and cleanup
- A JSON + self-contained HTML report: verdict, baseline-versus-lure diff, firewall timeline, ATT&CK table, patch diff.
- **CreateOS:** with `--publish`, a second small sandbox with **ingress** enabled serves the report on a public URL
  (`https://<sandbox>-8080.app.sb.createos.sh/<job>/`).
- **CreateOS:** the scan sandbox (and any forks) are **destroyed** in a `finally` block; `sandtrap gc` removes leftovers, because the Free plan
  allows 5 concurrent sandboxes and paused ones count.

### The static layer (binaries)
For C targets: **CreateOS** compiles with `gcc` inside the VM, and the **capa** standalone binary (Mandiant) runs inside a 2 GB sandbox to list
capabilities mapped to ATT&CK, merged into the same findings table.

---

## 5. CreateOS Sandbox cheat sheet

**What it is.** A hosted API that gives you a Linux **Firecracker microVM** in seconds: its own kernel (so a hostile program cannot reach the host
or your laptop), a command API, a files API, a per-sandbox firewall, pause/resume/fork, and public URLs. Python SDK: `createos-sandbox` (`from
createos import Client`). We use the EU endpoint `https://api-eu.sb.createos.sh`.

| CreateOS feature | What Sandtrap does with it | Why it matters (say this) |
| --- | --- | --- |
| **Create / destroy** | One fresh microVM per scan, destroyed in `finally`; `gc` cleans leftovers | Disposable and cheap: hostile code never survives a scan, and a new scan starts clean |
| **Own kernel (microVM)** | `strace`, `iptables`, `date -s`, `gcc` all work **as root** | A container cannot safely change the clock or firewall; we need real root inside a real VM |
| **Command API** | Every install, probe, compile and patch step | The agent's hands |
| **Files API** | Uploads the analyzer, the package, the driver code; downloads event logs | How evidence leaves the VM safely |
| **Egress control (set_egress)** | Registry-only during install, then **block all**; every change recorded and read back | The safety guarantee: the real internet is unreachable from a sample, provably |
| **Pause + fork** | Snapshot the prepared lab, clone it into 3 parallel sandboxes to race hypotheses | Test three guesses at once, each with identical state, in about 5 to 15 s per clone |
| **Ingress / preview URL** | A small sandbox serves the report on a public HTTPS URL | Shareable evidence with no extra hosting |
| **Shapes** | `s-1vcpu-2gb` for analysis and capa; `s-1vcpu-256mb` for the report host | Right-size machines per job |
| **Stripe Projects provisioning** | `stripe projects add createos/free` and `createos/project` supply the account and credentials | The sandbox account arrived through the same CLI as the database and inbox |

**Behaviour we measured on the Free plan (good to quote, all in `docs/DECISIONS.md`):**
- Pause takes about 7 to 9 s; a fork takes about 5 to 15 s to wake **with state preserved**. Under simultaneous forks the platform may park a
  child as "paused"; Sandtrap resumes it.
- The concurrent quota is 5 (paused sandboxes count), although the pricing page suggests one. Fork-and-race falls back to sequential probes if forks are refused.
- An empty egress allowlist means *allow all*; `["192.0.2.1:9"]` is our "block everything".
- Forks get random platform names; names are limited to 22 characters.
- Environment variables must be declared at creation, so Sandtrap exports the canary variables inside the scripts instead.
- Docker-in-sandbox, `iptables` NAT, `date -s` and ingress all work.
- **Public sandboxes we deployed for the hackathon (report host, API, evidence site) later showed as `destroyed` on the platform**, so a public
  CreateOS URL should be treated as temporary: redeploy and test right before you rely on one (`scripts/deploy_site.py`).

**Why not Docker / a container / a plain VM?** Containers share the host kernel (escape risk, and you cannot set the clock or firewall as you like).
A plain cloud VM takes minutes to start, costs per hour and has no live egress API. CreateOS gives VM-grade isolation with container-like speed
and a firewall you can change in one call, which is the whole trick of the lure.

---

## 6. The six ideas to explain simply

1. **Gate.** The condition a sample waits for before it misbehaves: `CI` is set, a domain resolves, the date has passed, `NODE_ENV` hashes to a
   value, a debugger is absent. XZ's backdoor, for instance, only acted when `TERM` was unset and `argv[0]` was `/usr/sbin/sshd`.
2. **Lure.** The fake world that satisfies the gate: DNS answers, an HTTP sink, a fake clock, CI variables. It lives entirely on loopback inside the sandbox.
3. **Canary.** A fake credential with a unique token (`SNDTRP-<8 hex>-AWS`). If the token shows up in captured traffic, the sample stole it. Proof, not inference.
4. **Deterministic verdict.** The LLM proposes experiments; plain code decides. That makes results auditable and immune to prompt injection from the sample.
5. **Baseline versus lure diff.** Behaviour that appears *only after* the agent changed the environment is the evidence of evasion.
6. **Remediation with proof.** The patch is verified by re-running the same attack, not by trusting the model.

Small analogy for each if you need it: gate = a bouncer's guest list; lure = a film set; canary = marked banknotes; deterministic verdict = a
referee who watches the replay rather than listening to the players.

---

## 7. The recorded demo, scene by scene

<!--REEL-->

---

## 8. Numbers to memorise

- **14 test samples** (12 malicious, 2 clean): Sandtrap detects **12/12**; a plain sandbox view detects **4/12**. Both clean samples stay clean.
  (The 4 a plain sandbox catches are the ones that act without any condition; the rest, including the compiled binary, look "clean" or only
  "inconclusive" to it.)
- **Real software** (public packages and installers, scanned as published): `six`, `requests`, `click`, `pyyaml`, `core-js`, `nodemon` all
  **clean**; nvm `install.sh` **inconclusive** and `rustup-init.sh` **suspicious** (they download code by design).
- **A scan takes about 30 to 80 seconds** on the fixtures (median 37 s), about one to three minutes on real packages; **4 to 6 LLM calls** on a
  fixture, more on a real package; **one CreateOS sandbox per scan** (plus up to three forks when racing, plus one when publishing).
- **87 unit tests** pass. 12 fixtures malicious, 2 benign.
- **Fork-and-race:** three hypotheses tested at once, about 38 s end to end in a live test.
- **Stripe Projects:** 3 services, all on free plans.
- **Verdict values:** `malicious`, `suspicious`, `clean` (with low confidence unless proven), `inconclusive`.

---

## 9. Stripe Projects and the stack

**Stripe Projects** is a CLI (`stripe projects ...`) that provisions third-party services for a project and syncs credentials into `.env`.
We added three services, all on free plans (`.projects/state.json`, status in `docs/proof/stripe-projects-status.txt`):

| Service | Command | What it does for Sandtrap |
| --- | --- | --- |
| **CreateOS** | `stripe projects add createos/free`, `createos/project` | The Sandbox API account: **every scan runs here** |
| **Neon Postgres** | `neon/free`, `neon/postgres` | LangGraph checkpoints for every run (falls back to memory) |
| **AgentMail** | `agentmail/free`, `agentmail/api` | The agent's inbox: email a package name, get the verdict and a report link back (6 scans/hour limit) |

The stack can be reproduced with the share URL `https://projects.dev/s#v1:AgentMail~api,createos~project,Neon~postgres`.

**Rest of the stack:** Python 3.13 + uv; LangGraph (pipeline and checkpoints); Gemini 3.5 Flash via Vertex AI for the analyst (K2 and Groq work via
`LLM_PROVIDER`); FastAPI with Server-Sent Events; an MCP server (`scan_package`, `get_report`); Langfuse tracing of every agent step; capa for binaries;
a threat memory in SQLite; HTML/JSON reports; 87 unit tests.

---

## 10. Honest limits, and what not to claim

**Say these yourself before anyone asks:**
- The samples in the benchmark are **harmless simulations we wrote** that model the behaviour reported in real incidents. They show the
  mechanism works; they are **not** a detection rate on real-world malware.
- Our claims about Codecov, `ctx`, XZ and the rest are **counterfactuals**: the original samples are gone, so we reproduced the *reported
  behaviour* and showed the lab surfaces it. Do not say "Sandtrap would have caught XZ".
- HTTPS bodies are unreadable (we log the TLS server name only). Samples that detect `strace` or validate DNS answers can stay quiet; those runs
  come out `inconclusive` or `clean` with **low confidence**, never "safe".
- Installers that download code (nvm, rustup) come out `inconclusive` / `suspicious`. That is intentional: a stealer also downloads and runs code.
- Credentials *printed to output* (the `tj-actions` incident) are not flagged yet; only network exfiltration is.
- Our first run on real software was wrong (core-js, nvm and rustup came out "malicious") because the analyst's own commands counted as evasion;
  we fixed the scorer and wrote it up (`docs/DECISIONS.md`, entry 18). That is a strength: say it.
- Rate limits: the Vertex model API sometimes answers with `429 resource exhausted`. An intermittent scan crash (`'list' object has no attribute 'get'`) turned out to be our own
  transport shim choking on that error (Vertex sends some errors as a JSON array). It is fixed, covered by a test, and the client now retries 429s with backoff.
- The analyst needs an LLM login (Gemini through the author's gcloud, or K2). The public API we deployed had no keys, so it could not scan.
- The skill memory is a working mechanism with no measured speed-up. The Free plan has a 5-sandbox quota and the public sandboxes expire.

**Do not claim:** "AI decides the verdict" (it does not); "production ready"; "catches all malware"; a percentage on real malware; "no false
positives"; that the demo is live (it is a recorded run: say so up front).

---

## 11. Questions you will get

**How is this different from VirusTotal, Any.run, Socket or a normal sandbox?**
Those either match known signatures or run the sample once. Sandtrap's agent *changes the environment* based on what the code appears to wait for, and
proves theft with canaries. A plain sandbox sees nothing from a gated sample; ours showed 12/12 vs 4/12.

**Can the malware escape the sandbox?**
Each sample runs in a CreateOS Firecracker microVM with its own kernel, with the firewall locked before analysis; the fake network exists only on loopback. We
never run samples on the host. We are not claiming hypervisor escapes are impossible, only that the blast radius is one disposable VM with no real credentials in it.

**What if the sample tries to trick the AI?**
The AI never decides the verdict, and everything a sample prints is sanitised, fenced and ignored by the scorer. We have a fixture that prints an injected
"verdict=clean" instruction; it still comes out malicious.

**Why CreateOS?**
We need (1) real root in a VM with its own kernel to run `strace`, `iptables`, `date -s` and `gcc`; (2) a firewall we can change live; (3) pause and
fork to test hypotheses in parallel; (4) public URLs for reports; (5) cheap disposable machines. That is the CreateOS feature set; a container or a standard cloud VM misses at least two.

**How many sandboxes does a scan use, and what does it cost?**
One per scan (up to three extra clones when racing, one more to publish), all destroyed afterwards. We ran everything on the Free plan with no payment method. LLM cost is a handful of Gemini Flash calls.

**What about false positives?**
Real packages came out clean; installers that download code are flagged as inconclusive/suspicious. The scorer only calls "evasion" when the sample itself does
something sensitive only under the lure. See the real-world table.

**Does it work on real malware?**
We tested harmless simulations of the reported behaviours and real benign software. We did not scan live malware, deliberately. The roadmap includes more real-world corpora.

**Why not static analysis?**
Static analysis misses obfuscated and gated code. We do include static analysis (capa) for binaries and combine it with dynamic proof.

**Can a coding agent use it?**
Yes: the MCP server exposes `scan_package` and `get_report`, so an agent can ask Sandtrap before it runs `pip install`. This matters for slopsquatting, where
models recommend packages that do not exist.

**What is "fork-and-race"?**
When the gate is unknown the agent forks the prepared sandbox into three clones with identical state and tests three hypotheses simultaneously, then destroys the clones.

**What would you build next?**
HTTPS interception for request bodies, a hardened Docker-per-sample layer inside the sandbox, a decompiler for stripped binaries, similarity search over past scans, and a sender allow-list for the email intake.

**Is the code open?** Yes, MIT: `github.com/hatif03/createos-stripe-hackathon`.

**Why is the demo recorded?** "To keep a live demo on X from depending on network latency; every frame is a replay of a real run, the proof for each is in the repo."

---

## 12. Glossary

| Term | Meaning |
| --- | --- |
| **Sandbox / microVM** | A small virtual machine with its own kernel. Here: a CreateOS Firecracker microVM. |
| **Egress** | Outbound network traffic. "Egress control" = which destinations a sandbox may reach. |
| **Ingress** | Inbound traffic; enabling it gives a sandbox a public URL. |
| **strace** | A Linux tool that logs a program's system calls (files opened, processes started, connections attempted). |
| **Canary** | A planted fake secret with a unique token, used to prove theft. |
| **Sink** | Our fake server inside the sandbox that accepts and logs whatever a sample sends. |
| **Lure** | The fake environment (DNS, env vars, clock, sink) built to make a sample act. |
| **Gate** | The condition a sample waits for before acting. |
| **ATT&CK** | MITRE's catalogue of attacker techniques (for example T1041 exfiltration, T1552.004 private keys, T1497 sandbox evasion). |
| **capa** | Mandiant's tool that lists what a binary can do. |
| **LangGraph** | The framework that runs our pipeline as a graph with saved checkpoints. |
| **MCP** | Model Context Protocol: how coding agents call external tools. |
| **Stripe Projects** | A Stripe CLI that provisions third-party services and syncs credentials. |
| **Slopsquatting** | Attackers registering package names that AI models hallucinate. |
| **Fork-and-race** | Clone a prepared sandbox into several and test hypotheses in parallel. |

---

## 13. Going live: checklist

- [ ] Say up front that the demo is a **pre-recorded run of the real application** (agreed with the organisers); the replay lengths are real except idle waits over 5 s.
- [ ] Have `media/demo/sandtrap-demo-reel.mp4` open (or the individual clips) and `docs/PROOF.md` and the repo in tabs for questions.
- [ ] Do **not** rely on a public CreateOS URL unless you redeployed and tested it in the last hour (the earlier ones expired; see section 5).
- [ ] Know your first and last sentences by heart; improvise the middle with the cheat sheet.
- [ ] Mention the three Stripe Projects services and name CreateOS at every stage; point at the blue banner.
- [ ] If a question is outside this guide, say what you know and what the repo's `docs/DECISIONS.md` records; do not guess numbers.

---

## 14. Where the proof is

| Claim | Evidence |
| --- | --- |
| Recorded runs and what CreateOS did in each | `docs/proof/demo/<run>/` (report, `sandbox-lifecycle.txt`, `meta.json`) and `media/demo/` |
| 12/12 vs 4/12 | `docs/BENCHMARK.md`, `docs/proof/bench.json`, 14 reports in `docs/proof/` |
| Real packages and installers | `docs/PROOF.md`, `docs/proof/pypi-*.html` etc. |
| Stripe Projects services | `docs/proof/stripe-projects-status.txt`, `.projects/state.json` |
| Tests, doctor | `docs/proof/unit-tests.txt`, `docs/proof/doctor.txt` |
| Design decisions and honest mistakes | `docs/DECISIONS.md` (18 entries), `docs/DEVLOG.md` |
| Real incidents (sourced) | `docs/USE-CASES.md`, README |
