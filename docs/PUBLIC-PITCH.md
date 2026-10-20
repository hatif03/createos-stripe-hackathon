# Public pitch video: timeline and narration

Video: `media/pitch/sandtrap-pitch.mp4`, 5:03, 1080p, silent. Built by `python scripts/render_pitch.py` from two real runs (a Python package and a compiled C binary),
one fork-and-race run, and story cards for the problem, the benchmark, real software, CreateOS and the limits. Replays of captured terminal output; waits over 5 seconds are shortened.

| Time | Length | Scene |
| --- | --- | --- |
| 0:00 | 6 s | Title |
| 0:06 | 15 s | Real incidents: Codecov, ctx, event-stream, XZ |
| 0:21 | 11 s | Why normal sandboxes miss it |
| 0:32 | 17 s | How Sandtrap works, with the CreateOS feature at every step |
| 0:49 | 67 s | **Run 1:** Python package with an environment-gated stealer (scan, proof, patch) |
| 1:56 | 18 s | The public report, served by a CreateOS sandbox |
| 2:14 | 56 s | **Run 2:** a compiled C binary, built and analysed inside the sandbox (capa) |
| 3:10 | 37 s | Fork-and-race: pause, fork three sandboxes, three guesses at once |
| 3:47 | 13 s | Where you can use it (CLI, API, MCP, email) |
| 4:00 | 15 s | Benchmark: 12 of 12 vs 4 of 12 |
| 4:15 | 12 s | Real software: packages clean, installers flagged |
| 4:27 | 15 s | Why CreateOS Sandbox (and the three Stripe Projects services) |
| 4:42 | 12 s | Safe by design, honest limits |
| 4:54 | 9 s | Close |

## Narration (the timestamp is when each part starts)

**[0:00]** This is Sandtrap: an AI analyst that catches malware that plays dead. **[0:06]** Codecov, ctx, event-stream, XZ. Different attacks, one trick: behave only when the environment looks real. Each one got past testing because nothing looked wrong. **[0:21]** A normal sandbox runs code once, sees nothing, and says clean. But evasive code checks first: is this a CI machine, does that domain resolve, what's the date? **[0:32]** Sandtrap works like a human analyst. It installs the package in a fresh CreateOS sandbox and seals the firewall. Then an AI changes the world until the code shows itself: a fake internet, a fake clock, fake credentials. And finally it patches the problem and checks the fix. **[0:49]** Here's a real run. This Python package does nothing in a plain run. Sandtrap creates a CreateOS sandbox, installs the package with only the package registries reachable, then closes the firewall completely. The baseline is quiet, and a normal sandbox would stop right here. The agent reads the code and guesses what the package is waiting for: a CI variable, and a hostname that resolves. Its first guess even has the wrong variable name, and it corrects itself on the next try. So it builds that world inside the VM and runs the package again. And there: the fake credentials we planted land in our trap. That's proof. The verdict comes from code, not from the AI. Then the agent patches the package and re-runs the same attack in the same sandbox, and nothing leaves. **[1:56]** Every scan produces a report. This one is served by a second CreateOS sandbox on a public link: what only appeared after we changed the environment, the credentials we caught, the attack techniques, and the patch. **[2:14]** Second run: a compiled C program. The source is compiled inside the sandbox, so the binary never touches your machine. A static analyser lists what it can do, and then the same trap proves what it actually does: it reads cloud credentials and tries to send them out. A plain sandbox calls this binary clean. **[3:10]** When the trigger is unknown, Sandtrap pauses the sandbox and forks it into three identical clones, and tests three guesses at once. Only the production guess makes the sample act. Then the clones are destroyed. **[3:47]** You can use it from the command line, through an API, as a tool your AI coding assistant calls before it installs anything, or by emailing a package name. **[4:00]** On our fourteen test samples, a plain sandbox catches four of the twelve malicious ones. Sandtrap catches all twelve, and both clean samples stay clean. **[4:15]** On real software, six popular packages come out clean, and real installers like nvm and rustup get flagged, because they download code. **[4:27]** None of this works without CreateOS: disposable VMs with real root access, a firewall we can change live, pause and fork, and public links. It was all provisioned with Stripe Projects: CreateOS, Neon and AgentMail. **[4:42]** It's safe by design: harmless samples, no real internet, fake credentials. And we're honest about the limits: these are simulations, not live malware, and code that detects tracing can still hide. **[4:54]** Sandtrap: make evasive code show itself, prove it, and fix it. It's open source on GitHub.

Notes for recording the voice-over: the run 1 section is about 140 words for 67 seconds, so leave room to pause while the panels appear. The "first guess has the wrong variable name" line is true of the recorded run
(experiment r1 used `MD_CI`, experiment r2 used `CI`); if you re-record the footage, check that claim against the new run before saying it.
