# Live Discord demo: commands, in order

Project: **Sandtrap**. Repo root: `D:\createos-stripe-hackathon`. Shell: PowerShell.

Slot: **5 minutes demo, then 3 minutes Q&A.** On the call you type two commands. Everything else is before you go live, or only if something breaks.

Do not run `stripe projects env` on the call. It prints credentials.

Rehearsed on 29 Oct 2026. Stripe, CreateOS, Neon, and the public report all worked. Gemini did not: Vertex returns 403 until billing is enabled on project `project-f0b6b4ce-541f-43ff-9f7` ([enable billing](https://console.developers.google.com/billing/enable?project=project-f0b6b4ce-541f-43ff-9f7)). The scan that matches the demo used K2 instead, finished in 49 seconds, and printed `MALICIOUS`, proof, and a passing patch. Run only one scan at a time. Two at once made K2 reject the patch step.

---

## 1. Before you join (about 15 minutes)

Run these from the repo root, top to bottom, in the terminal you will share. Wait for each one to finish. Leave this terminal open. The K2 setting lasts only for this window.

```powershell
cd D:\createos-stripe-hackathon
```

```powershell
$env:LLM_PROVIDER = "k2"
```

```powershell
uv run python -m src.cli.sandtrap gc --all
```

You want `removed N sandbox(es)`. The free plan allows 5 sandboxes at once. Leftovers will make the live scan fail.

```powershell
uv run python -m src.cli.sandtrap doctor
```

You want every line **OK**, including `llm  k2:IFM/K2-Horizon-375B-A23B answered` and `leftover sandboxes  0`. If `llm` is FAIL, do not go live on this terminal.

```powershell
stripe projects status
```

You want three providers, all **OK Linked**: createos, Neon, AgentMail. Three services, all **Free**.

```powershell
uv run python -m src.cli.sandtrap scan fixtures/gated-stealer --publish
```

This is the rehearsal. It creates a CreateOS sandbox, the agent writes and runs an experiment inside it, then a second sandbox hosts the report. Expect **malicious**, `patch verification` with `smoke-test=pass`, and a line `public report: https://...`. Open that URL and confirm the page says MALICIOUS. Then close the tab. A fresh URL is printed during the live scan. This fixture took 49 seconds on the rehearsal. A scan still running at 90 seconds is late; use the video backup.

```powershell
uv run python -m src.cli.sandtrap gc --all
```

```powershell
Set-Clipboard -Value "uv run python -m src.cli.sandtrap scan fixtures/gated-stealer --publish"
```

```powershell
cls
```

Leave the terminal on this empty prompt. Font 18 pt or larger. Window maximised.

Open, left to right, and do not close them:

1. This terminal.
2. The hackathon video, paused at the start, in a browser. This is the backup. Do not play it unless the live scan fails.
3. `docs\BENCHMARK.md` (for Q&A: 12 of 12 versus 4 of 12).

Turn on Focus Assist. Close chat and mail.

---

## 2. Dry run (screen share and audio)

Do this in a Discord channel with one other person, or with your own mic test, before the organisers join.

1. Join voice. Share the **terminal window**, not the whole screen.
2. Say one sentence out loud: "Can you hear me, and can you read the prompt?"
3. Confirm they can hear you and read the font.
4. Stop the share. Stay in the channel.

---

## 3. On the call: type these, and nothing else

Clock starts when you start speaking. Words are in `docs/LIVE-DISCORD-SCRIPT.md`. Use the same terminal where you set `$env:LLM_PROVIDER = "k2"`. A new window will call Gemini and the scan will fail.

**Command 1.** Paste is fine. Say the Stripe lines while the table is on screen. About 20 seconds.

```powershell
stripe projects status
```

**Command 2.** Paste from the clipboard (`Ctrl+V`), then Enter. This is the live demo. Do not start a second scan.

```powershell
uv run python -m src.cli.sandtrap scan fixtures/gated-stealer --publish
```

Watch the terminal. Speak when each of these appears. Do not type while it runs.

| When you see this | What just happened |
| --- | --- |
| `setup` / `install` | A CreateOS microVM was created. The package installed under strace. Only the package registries were reachable. |
| `egress locked` | The firewall closed. The real internet is unreachable. |
| `baseline` | First run. The package did nothing. |
| `agent tool: read_file` then the magenta **hypothesis** panel | The agent read the code and wrote the next experiment. That experiment runs inside the same sandbox. |
| **PROOF** | The planted fake credentials landed in the trap. |
| green **agent summary** | The model summarised. It does not choose the verdict. |
| `patch verification` then the red **SANDTRAP VERDICT** | The agent wrote a patch and re-ran the same attack. Expect `exfiltration=no`, `smoke-test=pass`, and `MALICIOUS`. If the panel says `Remediation step failed`, the proof still stands. Say that the patch step failed on this run. |
| `public report: https://...` | Open that URL. It is a second CreateOS sandbox. |

If the verdict is on screen before 3:30, open the report URL and stay there until you close. If the scan is still running at 4:15, do not open the report. Finish the last spoken lines over the verdict when it lands.

Stop at 5:00. Take questions. Do not type during Q&A unless someone asks to see a file you already have open (`docs\BENCHMARK.md`).

---

## 4. If the live scan breaks

In the first 30 seconds, once:

```powershell
uv run python -m src.cli.sandtrap gc --all
```

Then paste the scan command again.

If it fails a second time, or you are past 1:00, do not retry. Stop the share, share the browser with the hackathon video, press play, and say: "I'll play the recorded run. Same application, captured from a real scan."

After the call, either way:

```powershell
uv run python -m src.cli.sandtrap gc --all
```
