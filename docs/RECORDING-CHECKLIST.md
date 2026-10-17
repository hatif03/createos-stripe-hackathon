# Recording checklist (follow top to bottom)

Deadline: submissions lock **17:30 PT = 06:00 IST**. Demos are at 18:00 PT. The video must be **2-3 minutes** and **you must be on camera**.
Target: finish recording by about **04:30 IST** so the upload, post and form have an hour of slack.

Everything in `code blocks` is run from the repo root `D:\createos-stripe-hackathon` in a terminal.

---

## A. Before you record (about 25 minutes, off camera)

### A1. Tools
- [ ] Screen recorder ready (OBS, or Windows `Win+Alt+R`). Camera + microphone work. Record at 1080p, 30 fps.
- [ ] Close notifications (Windows Focus Assist on), close chat apps, hide bookmarks, no personal tabs open.
- [ ] Terminal font **18 pt or larger**, dark theme, window maximised. Run `clear` before every take.
- [ ] Browser zoom 125%.

### A2. Check the project is healthy
1. `git status` shows a clean tree and `git log --oneline | head -3` shows the latest commits.
2. `uv run python -m src.cli.sandtrap gc --all` (destroys leftover sandboxes so the Free quota of 5 is empty).
3. `uv run python -m src.cli.sandtrap doctor`: you want all 7 lines **OK**.
4. `uv run pytest tests/unit -q` ends with `87 passed`.
5. If the LLM check fails: run `gcloud auth login` (account with the Gemini access) and retry. Last resort: set `LLM_PROVIDER=k2` in `.env`.

### A3. Warm up so nothing is slow on camera
1. `uv run python -m src.cli.sandtrap scan fixtures/gated-stealer --publish`
   This is a **rehearsal** and also warms the public report host. Note the line `public report: https://...` (you will open it later), and confirm the verdict is `malicious`.
2. `uv run python -m src.cli.sandtrap gc --all` again.

### A4. Open these tabs (in this order, left to right)
1. **Terminal** (the one you will type in).
2. [docs/PROOF.md](PROOF.md) (the evidence page), in the VS Code Markdown preview or on GitHub.
3. `docs/BENCHMARK.md` (14 fixtures, 12/12 vs 4/12).
4. Langfuse dashboard, **Traces** list (shows the agent's runs; refresh it right after the live scan).
5. The README on GitHub (top part: "Real-world situations" table).
6. Stripe Projects: run `stripe projects status` in a second terminal tab so the output is already on screen.
7. The public report URL from A3 (a second one will be printed during the live scan; use the fresh one if it is up).

### A5. Do a dry run with a timer
Read the voice-over lines in VIDEO-TIMELINE.md once against `media/master-timeline.mp4` with a timer. Do not cut the live scan.

---

## B. While recording (four clips only; everything else is pre-rendered in `media/`)

The full minute-by-minute plan, the exact words and the editing steps are in [VIDEO-TIMELINE.md](VIDEO-TIMELINE.md). You record four things:

### Clip A: face intro (camera + mic), keep 14 s
- [ ] Say line 1 of the timeline ("Hi, I'm ... a normal sandbox ... calls it clean ... stays quiet"). Take 20 s so you can trim.

### Clip B: the live scan (screen + your voice), keep 65 s
- [ ] `clear`, then `uv run python -m src.cli.sandtrap scan fixtures/gated-stealer --publish`
- [ ] Narrate with the six beats in section 4 of the timeline (install and firewall closes, baseline quiet, hypothesis panel, proof, agent summary, patch and verdict).
- [ ] When it prints `public report: https://...`, stop recording. Keep the URL (it is in the report clip I rendered, but yours is the real one).
- [ ] If it stalls for more than 90 seconds: `Ctrl+C`, `uv run python -m src.cli.sandtrap gc --all`, retry once. If it fails again, use `media/live-scan-replay.mp4` (a real run, idle waits shortened) and say "recorded run" in the voice-over.

### Clip C: Langfuse (screen), keep 7 s
- [ ] Immediately after clip B open the Langfuse project, **Traces**, refresh, open the newest trace so its steps are visible. Record 15 s, keep 7.

### Clip D: face outro (camera + mic), keep 5 s
- [ ] Say line 10: "Fake credentials, no real internet. Code's in the repo."

### After each clip
- [ ] Play 5 seconds back: terminal readable, audio audible, face in frame.

---

## C. After recording (about 30 minutes)

1. Stitch clips, export MP4 1080p, **under 3:00**. Upload to YouTube as **Unlisted** (or Loom); copy the link and open it in a private window to confirm it plays.
2. **Cleanup:** `uv run python -m src.cli.sandtrap gc --all` (so no sandboxes stay alive).
3. **Publish the repo** (tell Claude "go" and it runs `gh repo create sandtrap --public --source . --push`). Then open the repo URL in a private window and check: README renders, no `.env`, `LICENSE` present.
4. **Post on X and LinkedIn** using `docs/POST-DRAFT.md` (replace `<repo link>`, attach or link the video, tag **@createosai** / CreateOS). Copy the post URLs.
5. **Submit the form** before 17:30 PT with: team name, Discord handle, project name **Sandtrap**, repo URL, video URL, post URL, and the one-line description:
   "Sandtrap is an AI analyst that lures evasive code into revealing itself inside CreateOS sandboxes, proves exfiltration with canary credentials, and patches it."
6. Screenshot the submission confirmation and keep it.

## D. If something breaks

| Problem | Fix |
| --- | --- |
| `429 concurrent quota reached` | `uv run python -m src.cli.sandtrap gc --all`, wait 10 s, retry |
| Scan hangs on the LLM | `Ctrl+C`, `gc --all`, retry once; else `LLM_PROVIDER=k2` in `.env` |
| Public report URL 404 | rerun with `--publish`, or `uv run python -m src.cli.sandtrap publish out/<job>` |
| Gemini auth error | `gcloud auth login`, then retry |
| Anything else | show `docs/proof/fixture-gated-stealer.html` and say it is a pre-run; judges care that the idea and evidence are real |
