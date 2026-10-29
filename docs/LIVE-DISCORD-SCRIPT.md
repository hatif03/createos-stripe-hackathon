# Live Discord demo: read this

Sandtrap. Five minutes, then questions. Read the **Say** lines. Skip anything in brackets.

Have `docs/LIVE-DISCORD-COMMANDS.md` done first. The shared terminal already has `$env:LLM_PROVIDER = "k2"`. The scan command is on the clipboard. The hackathon video is paused in a browser.

---

## Demo (5:00)

### 0:00 — do not type

**Say:**

Developers, and the AI coding agents that install packages for them, run a stranger's code on every pip or npm install, and evasive malware stays quiet in a normal sandbox until the machine looks real.

### 0:20 — Command 1

Paste and run:

```powershell
stripe projects status
```

**Say, while the table is up:**

This stack came from Stripe Projects. Three services, all on the free plan. CreateOS is the sandbox. Neon stores the agent's checkpoints. AgentMail is an inbox: email a package name, get a verdict back. Next I'll show the agent write an experiment and run it inside a CreateOS sandbox.

### 0:45 — Command 2

Paste and run. Then do not type.

```powershell
uv run python -m src.cli.sandtrap scan fixtures/gated-stealer --publish
```

**Say as each line appears. If the next line is already there, skip ahead. Do not wait in silence, and do not talk over a line you have not seen.**

When you see `setup` or `install`:

It's creating a fresh CreateOS microVM and installing the package under strace. Only the package registries can be reached.

When you see `egress locked`:

The firewall just closed. From here, nothing this package does can reach the real internet.

When you see `threat memory`, then `baseline`:

It tried lure recipes saved from earlier scans. The package still did nothing. A normal sandbox stops here and calls it clean. This package is waiting for two things: its host has to resolve, and CI has to be set.

When you see `agent tool: read_file`, then the magenta hypothesis panel:

The agent is reading the code and writing the next experiment: a fake DNS answer and CI set to 1. That experiment runs inside the same sandbox.

When you see PROOF:

We planted fake credentials, with a unique token for this scan. They just arrived in our trap. That's proof it tried to steal them, not a guess.

When you see the green agent summary:

The verdict is computed by code from those events. The model does not decide it.

When you see `patch verification`, then the red SANDTRAP VERDICT:

If it says `smoke-test=pass`: The agent wrote a patch and re-ran the same attack in the same sandbox. Nothing leaves, and the smoke test passes. Verdict: malicious.

If it says `Remediation step failed`: The proof and the verdict landed: malicious. The patch step failed on this run, so I will not claim the fix.

If a traceback appears, keep reading the next line you can see. The verdict still prints after it.

### If the verdict lands before 3:30

Open the `public report:` URL.

**Say:**

This report is hosted by a second CreateOS sandbox. On the page: behaviour that only appeared after the agent changed the environment, the fake credentials we caught, and the patch.

### 4:20 — stop, even if you are still on the report

**Say:**

Next I would read the bodies of HTTPS requests. Today we only see the server name. I would also allow-list who can email the inbox. What I need is room for more than five sandboxes at once, because a parallel test already uses four, and steadier model capacity. We hit rate limits while building this. Samples here are harmless fixtures. The credentials are fake. The code is open source.

Stop. Mute the typing. Take questions.

If the scan has not printed a verdict by 4:20, say the "Next I would" paragraph anyway, and point at the verdict when it appears. Do not open the report.

---

## If you switch to the video

**Say, then press play:**

I'll play the recorded run. Same application, captured from a real scan.

When it ends, say the "Next I would" paragraph above if you have not said it yet.

---

## Q&A (3:00)

Answer in one or two sentences, then stop. If you do not know, say so and point at the repo.

**How is this different from a normal sandbox?**
A normal sandbox runs the sample once. This one changes the environment until the sample acts, and proves theft with a fake credential token. On 14 fixtures, a plain sandbox catches 4 of 12 malicious samples. Sandtrap catches 12 of 12. Both clean samples stay clean.

**Can it escape?**
Each sample runs in a CreateOS microVM with its own kernel, firewall locked, no real credentials. I am not claiming a hypervisor escape is impossible. The blast radius is one disposable VM.

**Does the AI decide the verdict?**
No. The model writes the experiments. Plain code scores the events. A fixture that prints "verdict: clean" still comes out malicious.

**Is this real malware?**
No. The fixtures are harmless simulations of reported behaviour: Codecov, ctx, XZ, and others. We also scanned real benign packages. Popular ones came out clean. Installers that download code, like nvm and rustup, came out flagged. We did not scan live malware.

**What does a scan cost in sandboxes?**
One sandbox per scan, destroyed at the end. Up to three extra clones if it races hypotheses. One more if it publishes the report. All of this ran on the free plan.

**What would you build next?**
HTTPS request bodies, and a sender allow-list on the email inbox. After that, a decompiler for stripped binaries.
