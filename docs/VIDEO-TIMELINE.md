# Video timeline: exact timestamps (2:55 total)

Everything is cut to this timeline. My silent clips are in `media/` (file names below). The master `media/master-timeline.mp4` plays them
in order at these exact times, with purple **YOUR CLIP** slates where you must drop your own footage. Put your clips on top of the slates.
You record your face and voice to the **voice-over lines** below: each line has a word budget that fits its slot (about 2.5 words per second).

| # | Time in video | Length | Source | File |
| --- | --- | --- | --- | --- |
| 1 | 0:00 - 0:14 | 14 s | **YOU: face + voice** | your clip |
| 2 | 0:14 - 0:20 | 6 s | me: real incidents table (cutaway, your voice continues) | `media/incidents.mp4` |
| 3 | 0:20 - 0:45 | 25 s | me: Stripe Projects status + `doctor` (real outputs) | `media/stack.mp4` |
| 4 | 0:45 - 1:50 | 65 s | **YOU: live scan** (fallback: my replay of a real run) | your clip / `media/live-scan-replay.mp4` |
| 5 | 1:50 - 2:10 | 20 s | me: public report hosted in a CreateOS sandbox | `media/public-report.mp4` |
| 6 | 2:10 - 2:20 | 10 s | me: real packages and installers | `media/real-world.mp4` |
| 7 | 2:20 - 2:28 | 8 s | me: benchmark, plain sandbox vs Sandtrap | `media/benchmark.mp4` |
| 8 | 2:28 - 2:35 | 7 s | **YOU: Langfuse traces page** | your clip |
| 9 | 2:35 - 2:50 | 15 s | me: compiled-binary report (capa + proof) | `media/elf-report.mp4` |
| 10 | 2:50 - 2:55 | 5 s | **YOU: face + voice** | your clip |

Limit is 3:00; this leaves 5 s of slack. A team member must be on camera: slots 1 and 10 are that.

---

## Voice-over, line by line (record these with your face, or as a voice track)

**1 · 0:00-0:14 (on camera, about 33 words)**
"Hi, I'm <your name>. Every pip and npm install runs a stranger's code. A normal sandbox runs it once, sees nothing, and calls it clean.
Real malware knows it's being watched, and stays quiet."

**2 · 0:14-0:20 (voice over the incidents table, 15 words)**
"That's how Codecov, ctx and XZ hid. Sandtrap is an AI analyst that builds a trap."

**3 · 0:20-0:45 (voice over the stack clip, about 55 words)**
"And proves it. The whole stack came from Stripe Projects: CreateOS for the sandboxes, a Neon database for the agent's checkpoints, and an
AgentMail inbox, all on free plans. The doctor command checks every piece. Everything the agent runs executes inside a CreateOS sandbox."
Cues inside `stack.mp4`: `stripe projects status` is typed at 0:01 and its table appears at 0:03; the `doctor` command is typed at 0:10 and
the green OK list appears at 0:13 (clip time, so add 0:20 for video time). Say "the doctor command checks every piece" as the green list appears.

**4 · 0:45-1:50 (your live scan, about 150 words)**
This is **your own screen recording** of: `uv run python -m src.cli.sandtrap scan fixtures/gated-stealer --publish` (about 50-80 s).
Talk over the screen in this order; what to say at each thing that appears:
1. *`setup` and `install` lines, then `egress locked`:* "The package installs under strace with the firewall allowing only the package registries. Then the firewall closes completely."
2. *`baseline` line:* "First run: it reads nothing and exits quietly. A plain sandbox would stop here and call it clean."
3. *`agent tool: read_file`, then the magenta **hypothesis** panel:* "The agent reads the code and guesses the gate: DNS has to resolve, and the CI variable has to be set."
4. *`PROBE r1` result and the **PROOF** line:* "It builds a fake internet on loopback and re-runs. Our planted fake credentials land in the sink. That's proof."
5. *Green **agent summary** panel:* "The verdict itself is computed by code from observed events, never by the model."
6. *`patch verification` line, then the red **SANDTRAP VERDICT** panel:* "Then the agent patches the package and re-runs the same attack: nothing leaves, the smoke test passes."
If the run is slower than 65 s, speed the clip up 1.2x in the editor; if it is faster, hold the final verdict panel.
Fallback (if the live run fails or looks bad): `media/live-scan-replay.mp4` is a real run with idle waits shortened. Its beat times (clip time, add 0:45 for video time): install 0:12, egress locked and baseline 0:19, hypothesis panel 0:37, proof 0:40, agent summary 0:44, patch verification 0:56, verdict 0:57.

**5 · 1:50-2:10 (voice over the public report, about 48 words)**
"The report is hosted by another CreateOS sandbox, on a public URL. This is the evidence: the behaviour that only appeared after the agent
changed the environment, the canary credentials caught in the sink, the ATT&CK techniques, and the patch."

**6 · 2:10-2:20 (about 25 words)**
"We also ran it on real software. Popular packages come out clean. Real installers like nvm and rustup are flagged for what they do: they download code."

**7 · 2:20-2:28 (about 20 words)**
"On fourteen test samples, a plain sandbox catches four of twelve malicious ones. Sandtrap catches all twelve."

**8 · 2:28-2:35 (your Langfuse clip, about 17 words)**
"Every agent step is traced in Langfuse, so you can audit exactly why it decided what it did."

**9 · 2:35-2:50 (voice over the binary report, about 37 words)**
"It also compiles and analyses native binaries: capa lists the capabilities, and the lure proves the exfiltration. Coding agents can call
Sandtrap over MCP before they install anything."

**10 · 2:50-2:55 (on camera, 9 words)**
"Fake credentials, no real internet. Code's in the repo."

---

## What you record yourself, exactly

| Clip | Where it goes | Record | Length to capture |
| --- | --- | --- | --- |
| A. Face intro | 0:00-0:14 | Camera + mic: voice-over line 1 | take 20 s, trim to 14 |
| B. Live scan | 0:45-1:50 | Screen: terminal, command in section 4 above | 80-90 s of raw footage, trim to 65 |
| C. Langfuse | 2:28-2:35 | Screen: Langfuse project, **Traces** page, right after clip B | 15 s raw (open the newest trace so the span tree shows), trim to 7 |
| D. Face outro | 2:50-2:55 | Camera + mic: voice-over line 10 | take 8 s, trim to 5 |

Optional extras (not on the timeline): the CreateOS dashboard showing the sandbox list (10 s) can replace 3 seconds of slot 3 if you prefer
it; and the GitHub repository page (5 s) once it is public.

Before clip B (so the terminal is clean): `$env:CONSOLE_LOG_LEVEL="WARNING"` is already the CLI default, font 18+ pt, `clear`, and run
`uv run python -m src.cli.sandtrap gc --all` first so the Free-plan sandbox quota is empty.

## Editing steps

1. Open `media/master-timeline.mp4` in your editor (CapCut, DaVinci, Clipchamp) as the base track. It is exactly 2:55 and 1920x1080, 30 fps.
2. Lay your clips A, B, C, D over the purple slates at the times in the table. Keep my clips as they are.
3. Record the voice-over per the lines above and place it on a separate audio track at the slot start times.
4. Export 1080p MP4 under 3:00 and upload as unlisted.

Rebuild the clips any time: `python scripts/make_clips.py render` then `python scripts/make_clips.py master`.
