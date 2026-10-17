# Decision log

Each entry: context, decision, **tradeoffs**. Evidence for every number is in [DEVLOG.md](DEVLOG.md) and [BENCHMARK.md](BENCHMARK.md).

## 1. Build an adaptive analyst, not another scanner
- **Context:** Package scanners and sandboxed dynamic analysis already exist; a plain "run it and report" sandbox calls evasive code clean.
  "Should I install this?" was also a listed hackathon idea, so a plain version would be crowded.
- **Decision:** the agent plays analyst: it changes the environment (DNS, env vars, clock, fake internet) until the sample shows itself, then
  proves it with canary credentials and patches it.
- **Tradeoffs:** + a clear "agent writes, runs and fixes its own code" story where egress control is the safety guarantee; - more moving parts
  than a scanner (lure server, parser, fixtures) and the claim must be backed by evidence, hence the benchmark.

## 2. The verdict is computed by code, never by the model
- **Decision:** `score.py` derives verdict, score, confidence and ATT&CK mapping from observed events. The model produces hypotheses, drivers,
  patches and the summary only. Everything a sample prints is sanitised and fenced before the model sees it.
- **Tradeoffs:** + prompt injection in a sample cannot flip a verdict (a fixture asserts it), evidence is auditable; - less "AI magic" in the
  verdict itself: the agent's value is making behaviour observable, which is the hard part.
- **Learned from real scans:** a quick quiet exit only counts as suspicious if no lure experiment ran; persistence writes at import are
  *intent*; install-time registry traffic and the sandbox resolver are not outbound signals; durations in event text must not look like
  behaviour differences (a fabricated evasion finding made a clean fixture "malicious" until fixed).

## 3. Proof by canary tokens, lure on loopback
- **Decision:** fake credentials with a fresh per-scan token are planted; a loopback DNS stub plus a sniffing TCP sink (HTTP bodies, TLS
  server names, raw bytes) and an `iptables` catch-all capture what a sample sends. The sink scans bodies for the token (plain, URL-encoded,
  base64).
- **Tradeoffs:** + exfiltration is provable and nothing real is ever reachable; - HTTPS bodies are unreadable without interception (only the
  server name is logged) and only planted credential types are covered.

## 4. Egress policy by phase, "block all" as an unroutable rule
- **Context:** an empty allowlist means *allow all*; rules are `host:port`.
- **Decision:** registry-only during install (so install hooks are traced but cannot reach arbitrary hosts), then `set_egress(["192.0.2.1:9"])`
  (TEST-NET-1) for all analysis. Every change is recorded and read back from the platform into the report.
- **Tradeoffs:** + visible, auditable use of a headline sandbox feature; - DNS-name rules for CDN-hosted registries may be fragile, so install
  traffic to the registry CDN is filtered out of scoring.

## 5. `strace` inside the sandbox for behaviour capture
- **Decision:** `strace -f` with a parser that runs in the sandbox; no language-level hooks.
- **Tradeoffs:** + sees native code and child processes, and records *attempted* connections even when the firewall blocks them; - noisy output
  (filtered at parse time) and tracer-aware samples can behave differently.

## 6. Fork-and-race, with a sequential fallback
- **Context:** pause takes 7-9 s, a fork needs 5-15 s to wake with state preserved; under three simultaneous forks one child was parked as
  `paused` by the platform; the account quota is 5 concurrent sandboxes (paused ones count); forks get random platform names.
- **Decision:** snapshot the installed sandbox, fork up to three clones in parallel threads, resume parked children, run one hypothesis per clone,
  destroy the clones, resume the parent; fall back to sequential probes if forks are refused. `gc` removes leftovers including forks.
- **Tradeoffs:** + shows fork, pause and resume doing real work (38 s to race three guesses in a live test); - slower than a single probe, and it
  depends on a quota that may change. The README states the observation instead of claiming Free = one sandbox.

## 7. Remediation with proof
- **Decision:** after a proven catch the agent writes a patch; the lab applies it to the installed copy, re-runs the exact lure and a smoke
  test, and the report only claims success if nothing leaks and the smoke test passes.
- **Tradeoffs:** + closes the loop (detect, prove, fix, verify) and exercises "fixes its own code"; - pure-Python packages only for now.

## 8. LLM: Gemini 3.5 Flash through Vertex AI
- **Context:** K2 ignores `response_format: json_schema`, leaks reasoning into content on long prompts and is slow on long contexts; Gemini 3.x
  rejects multi-turn tool calls unless the `thought_signature` is sent back, which LangChain drops; `gemini-4-argon` blocks security prompts
  with a content filter.
- **Decision:** `ChatOpenAI` against the Vertex OpenAI-compatible endpoint, with an httpx transport that refreshes the gcloud token and
  re-injects the real thought signature (or Google's documented bypass value). 75 s timeout, one retry, low reasoning effort. `LLM_PROVIDER=k2`
  switches provider; there is no automatic cross-provider fallback.
- **Tradeoffs:** + fast, reliable tool calls and structured output; - depends on the author's gcloud login, small real billing, and a shim for a
  documented API quirk.

## 9. Threat memory and learned skills (a mechanism, not a claimed speed-up)
- **Decision:** SQLite stores a scan cache by sample hash, an indicator store and a skill library; after a proven catch the agent writes a skill
  whose lure settings come from the probe that actually produced proof (never from model text: a malformed model-written value crashed the first
  version). Later scans retrieve skills and try them first.
- **Tradeoffs:** + the agent extends its own toolkit; - on simple fixtures a sibling sample was *not* faster with the skill (2 probes against 1),
  so the README makes no speed claim.

## 10. Stripe Projects as the infrastructure layer: CreateOS, Neon, AgentMail
- **Decision:** the sandbox account, the Postgres database (LangGraph checkpoints, in-memory fallback) and the agent's inbox are provisioned with
  `stripe projects add`; `.projects/state.json` is committed and a share URL reproduces the stack. `sandtrap doctor` verifies it. The email intake
  validates targets with the API allow-list, rate-limits to 6 scans/hour and replies only with structured fields.
- **Tradeoffs:** + Stripe Projects does real work (credentials, a database, an inbox) instead of being a checkbox; - polling instead of a webhook,
  and anyone who knows the address can trigger scans within the rate limit (roadmap: sender allow-list).

## 11. Static layer: capa inside the sandbox
- **Decision:** the capa standalone binary (downloaded at setup, 47 MB) runs inside a 2 GB sandbox on compiled targets (3.9 s, 220 MB measured);
  its JSON is parsed structurally and merged into the same ATT&CK table. VirusTotal is a hash lookup that does nothing without a key.
- **Not built:** a decompiler (needs a JDK and about 600 MB) and Docker-in-sandbox execution (verified possible) are roadmap items.

## 12. Deep-research enrichment is optional and refuses to answer without sources
- **Context:** the first live run hallucinated dates and vendors because the scraping search backend failed; the answer looked authoritative.
- **Decision:** the search tool is Gemini's Google Search grounding (cited); the brief is withheld unless it contains a source URL; it runs only with
  `--enrich`, never on the verdict's critical path.

## 13. Untrusted data handling and public reports
- **Decision:** the API and MCP accept only allow-listed targets (`pypi:` or `fixture:`), never host paths or URLs. Reports escape every dynamic
  string. Public reports are served from a dedicated sandbox with ingress and contain only fake canary tokens and escaped sample output.

## 14. Free plan only, no spending
- **Decision:** no paid plan or payment method was added. Sandbox lifecycle is defensive: names are capped at 22 characters, every session is
  destroyed in `finally`, forks are tracked, `gc --all` cleans after crashes.
