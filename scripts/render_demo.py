"""Render the recorded demo runs into videos with a CreateOS banner (hackathon-built).

Input: media/demo/<name>.jsonl and docs/proof/demo/<name>/ from scripts/record_demo.py. Output: media/demo/<name>.mp4 for every run
and media/demo/sandtrap-demo-reel.mp4 (title, stack, every run, closing card). The videos are replays of the real captured terminal
output (idle waits over 5 s shortened); they are not screen recordings. Needs system Python with Pillow + markdown, ffmpeg, Edge.
Usage: python scripts/render_demo.py [name ...]
"""
import html
import importlib.util
import json
import re
import sys
from pathlib import Path

from PIL import Image, ImageDraw, ImageFont

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("mc", ROOT / "scripts" / "make_clips.py")
mc = importlib.util.module_from_spec(spec)
spec.loader.exec_module(mc)

DEMO = ROOT / "media" / "demo"
PROOF = ROOT / "docs" / "proof" / "demo"
W, H, FPS = mc.W, mc.H, mc.FPS
FOOT = 74
BLUE = (21, 101, 192)
ORDER = ["hero", "npm", "elf", "script", "real", "race", "mcp", "mail"]

BANNERS = [
    ("creating sandbox", "Firecracker microVM created through the CreateOS Sandbox API; egress allowlist: package registries only"),
    ("> install", "Untrusted code is installed INSIDE the CreateOS sandbox, traced with strace; only the registries are reachable"),
    ("> compile", "gcc runs INSIDE the CreateOS sandbox: the binary never exists on the host"),
    ("> upload", "The script is uploaded to the CreateOS sandbox with the files API; it only ever runs inside the VM"),
    ("install ok:", "Package installed INSIDE the CreateOS sandbox, traced with strace"),
    ("egress locked", "CreateOS egress control: set_egress() blocks every outbound packet from the sample; the policy is read back into the report"),
    ("> baseline", "Baseline run INSIDE the sandbox: fake DNS answers NXDOMAIN, every lookup is logged"),
    ("> static", "CreateOS 2 GB sandbox shape: capa static analysis runs inside the VM"),
    ("> analyst", "The agent reads the code through the CreateOS files and command APIs"),
    ("hypothesis", "Agent rebuilds the environment INSIDE the VM: fake DNS, loopback sink, CI variables, system clock (root, iptables, date -s)"),
    ("PROOF", "Canary credentials captured by the sink INSIDE the CreateOS sandbox; nothing left the VM"),
    ("> remediate", "Agent patches the package and re-runs the SAME attack in the same CreateOS sandbox"),
    ("patch verification", "Patch verified inside the sandbox: no canary leaves, smoke test passes"),
    ("SANDTRAP VERDICT", "Verdict computed by code from events observed in the CreateOS sandbox; the sandbox is destroyed after the scan"),
    ("public report", "CreateOS ingress: the report is served from another sandbox on a public URL"),
    ("event: race", "CreateOS pause + fork: the parent is paused, three clones race competing hypotheses in parallel, then are destroyed"),
    ("race took", "CreateOS fork-and-race finished: three hypotheses tested at once in three forked sandboxes"),
    ("MCP tools offered", "MCP: a coding agent asks Sandtrap before installing; every scan runs in a CreateOS sandbox"),
    ("Sandtrap answered", "The verdict came back from a scan that ran in a CreateOS sandbox and was destroyed afterwards"),
    ("scanner inbox", "AgentMail (via Stripe Projects): email a package name; the scan runs in a CreateOS sandbox and the reply carries the verdict"),
]
START_BANNER = "Sandtrap runs everything it analyses inside CreateOS sandboxes"
EMAIL = re.compile(r"[\w.+-]+@agentmail\.to")


class DemoTerminal(mc.Terminal):
    def __init__(self, title):
        super().__init__(title)
        self.rows = (H - self.BAR - 2 * self.PAD - FOOT) // self.LH
        self.banner = START_BANNER
        self.bold = ImageFont.truetype("C:/Windows/Fonts/segoeuib.ttf", 30)
        self.reg = ImageFont.truetype(mc.SANS, 30)

    def frame(self):
        img = super().frame()
        d = ImageDraw.Draw(img)
        d.rectangle([0, H - FOOT, W, H], fill=BLUE)
        d.text((28, H - FOOT + 18), "CREATEOS SANDBOX", font=self.bold, fill=(255, 255, 255))
        x0 = 28 + d.textlength("CREATEOS SANDBOX", font=self.bold) + 26
        size, font = 30, self.reg
        while d.textlength(self.banner, font=font) > W - x0 - 24 and size > 18:  # shrink the text until it fits on one line
            size -= 1
            font = ImageFont.truetype(mc.SANS, size)
        d.text((x0, H - FOOT + 18 + (30 - size) // 2), self.banner, font=font, fill=(225, 238, 255))
        return img


def banner_for(text, current):
    plain = mc.ANSI.sub("", mc.CSI_OTHER.sub("", text))
    for key, banner in BANNERS:
        if key in plain:
            return banner
    return current


def render_run(name):
    lines = [json.loads(l) for l in (DEMO / f"{name}.jsonl").read_text(encoding="utf-8").splitlines()]
    head, body = lines[0], lines[1:]
    plain = lambda t: mc.ANSI.sub("", mc.CSI_OTHER.sub("", t))
    body = [(e["t"], EMAIL.sub("agent-inbox@agentmail.to", e["text"])) for e in body
            if not plain(e["text"]).startswith(("Loading environment", "Loaded environment")) and not mc.LOGLINE.match(plain(e["text"]))]
    if name == "mcp":  # the MCP library adds its own log formatting on stderr; keep only the demo's own lines
        keep = ("MCP tools", "agent>", "Sandtrap answered", "verdict:", "confidence:", "proof level:", "findings:", "- ", "lure_only", "remediation:", "report:")
        body = [(t, x) for t, x in body if plain(x).lstrip().startswith(keep)]
    body = mc.compress(body, 5.0) if body else body
    shown = head["command"]
    shown = "uv run python -m " + shown if shown.startswith("src.cli.sandtrap") else "uv run python " + shown
    cmd, t_cmd = mc.typed(shown, 0.8, cps=45)
    cmd.append((t_cmd, chr(10)))
    events = [(t, x, None) for t, x in cmd] + [(t + t_cmd + 0.4, x, banner_for(x, None)) for t, x in body]
    term = DemoTerminal(f"{head['title']}  (replay of a real run, idle waits shortened)")
    import subprocess
    out = DEMO / f"_{name}_term.mp4"
    proc = subprocess.Popen(["ffmpeg", "-y", "-loglevel", "error", "-f", "rawvideo", "-pix_fmt", "rgb24", "-s", f"{W}x{H}", "-r", str(FPS), "-i", "-",
                             "-c:v", "libx264", "-pix_fmt", "yuv420p", "-crf", "20", str(out)], stdin=subprocess.PIPE)
    written = 0

    def emit(until):
        nonlocal written
        raw = term.frame().tobytes()
        while written < until:
            proc.stdin.write(raw)
            written += 1

    for t, text, banner in events:
        emit(int(t * FPS))
        term.feed(text)
        if banner:
            term.banner = banner
    emit(int((events[-1][0] + 3.0) * FPS))
    proc.stdin.close()
    proc.wait()
    return out


def proof_card(name):
    folder = PROOF / name
    meta = json.loads((folder / "meta.json").read_text(encoding="utf-8")) if (folder / "meta.json").exists() else {}
    rep = {}
    if (folder / "report.json").exists():
        rep = json.loads((folder / "report.json").read_text(encoding="utf-8"))
    life = [l for l in (folder / "sandbox-lifecycle.txt").read_text(encoding="utf-8").splitlines() if not l.startswith("#")] if (folder / "sandbox-lifecycle.txt").exists() else []
    ids = rep.get("sandbox_ids") or sorted(set(re.findall(r"sb-[0-9a-z]+", "\n".join(life))))
    eg = "".join(f"<tr><td>{html.escape(s['phase'])}</td><td><code>{html.escape(', '.join(s['rules']))}</code></td><td>{html.escape(s.get('note', ''))}</td></tr>"
                 for s in rep.get("egress_timeline", []))
    life_html = html.escape("\n".join(l[11:] if len(l) > 11 else l for l in life[:16]))
    verdict = rep.get("verdict", "")
    body = f"""<h1>What ran in CreateOS for this scan</h1>
<p class=sub>{html.escape(meta.get('title', name))} &middot; {meta.get('seconds', '?')} s &middot; exit {meta.get('exit_code', '?')}{(' &middot; verdict: <b>' + verdict.upper() + '</b>') if verdict else ''}</p>
<div class=big><div class=card><span class=sub>CreateOS sandboxes created</span><b class=good>{len(ids) or len(life)}</b><span class=sub>{html.escape(', '.join(i[-10:] for i in ids[:5]))}</span></div>
<div class=card><span class=sub>Destroyed after the run</span><b class=good>{'yes' if rep.get('destroyed', True) else 'no'}</b><span class=sub>Free plan quota freed</span></div></div>
{('<h2>Egress policy timeline (read back from the platform)</h2><table><tr><th>phase</th><th>allowed outbound</th><th>note</th></tr>' + eg + '</table>') if eg else ''}
<h2>Sandbox events from the application log (UTC)</h2><pre style="font-size:21px;color:#9ecbff">{life_html or 'see sandbox-lifecycle.txt'}</pre>"""
    page = DEMO / f"_{name}_card.html"
    page.write_text(mc.page(body), encoding="utf-8")
    png = DEMO / f"_{name}_card.png"
    mc.screenshot(page.as_uri(), png, height=1400)
    img = Image.open(png).convert("RGB").crop((0, 0, W, min(H, Image.open(png).height)))
    img.save(png)
    out = DEMO / f"_{name}_card.mp4"
    mc.still_clip(png, out, 8)
    return out


def title_card(path, text_lines, seconds):
    img = Image.new("RGB", (W, H), mc.BG)
    d = ImageDraw.Draw(img)
    d.rectangle([0, 0, W, 14], fill=BLUE)
    y = 250
    for size, line, color in text_lines:
        d.text((140, y), line, font=ImageFont.truetype("C:/Windows/Fonts/segoeuib.ttf" if size > 60 else mc.SANS, size), fill=color)
        y += int(size * 1.5)
    png = path.with_suffix(".png")
    img.save(png)
    mc.still_clip(png, path, seconds)


def concat(parts, out):
    lst = DEMO / "_concat.txt"
    lst.write_text("".join(f"file '{p.as_posix()}'\n" for p in parts), encoding="utf-8")
    mc.ffmpeg("-f", "concat", "-safe", 0, "-i", lst, "-c:v", "libx264", "-crf", 20, "-pix_fmt", "yuv420p", out)


def main(names):
    DEMO.mkdir(parents=True, exist_ok=True)
    mc.build_pages = lambda: None
    finals = {}
    for n in names:
        if not (DEMO / f"{n}.jsonl").exists():
            print("no capture for", n)
            continue
        out = DEMO / f"{n}.mp4"
        if not out.exists() or "--redo" in sys.argv:
            concat([render_run(n), proof_card(n)], out)
            print("rendered", out.name, flush=True)
        finals[n] = out
    if set(names) >= set(ORDER) or len(names) > 1:
        wh, bl, gy = (255, 255, 255), (120, 180, 255), (170, 180, 195)
        t_open, t_close = DEMO / "_title.mp4", DEMO / "_closing.mp4"
        title_card(t_open, [(84, "Sandtrap", wh), (44, "A recorded run of the real application", bl),
                            (36, "Every scan below ran inside CreateOS sandboxes; the blue banner says what each step uses.", gy),
                            (36, "Replays of captured terminal output; idle waits over 5 seconds are shortened.", gy)], 5)
        title_card(t_close, [(70, "What you just saw", wh), (38, "Firecracker sandboxes created and destroyed per scan, with live egress control", bl),
                             (38, "Pause + fork to race hypotheses, ingress for public reports, root inside the VM", bl),
                             (34, "Evidence: docs/PROOF.md and docs/proof/demo/ in github.com/hatif03/createos-stripe-hackathon", gy)], 7)
        parts = [t_open] + ([ROOT / "media" / "stack.mp4"] if (ROOT / "media" / "stack.mp4").exists() else []) + [finals[n] for n in ORDER if n in finals] + [t_close]
        concat(parts, DEMO / "sandtrap-demo-reel.mp4")
        print("reel written", flush=True)


if __name__ == "__main__":
    main([a for a in sys.argv[1:] if not a.startswith("--")] or ORDER)
