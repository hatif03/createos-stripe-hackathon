"""Render the public pitch video: story cards + two real runs + benchmark and real-software evidence (hackathon-built).

Reuses the recorded runs from scripts/record_demo.py (hero = Python package, elf = compiled C binary, race = fork-and-race) and the data in
docs/proof/. Output: media/pitch/sandtrap-pitch.mp4 and media/pitch/timeline.json. Needs system Python with Pillow + markdown, ffmpeg, Edge.
Usage: python scripts/render_pitch.py
"""
import importlib.util
import json
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def load(name, file):
    spec = importlib.util.spec_from_file_location(name, ROOT / "scripts" / file)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


mc = load("mc", "make_clips.py")
OUT = ROOT / "media" / "pitch"
DEMO = ROOT / "media" / "demo"
HOSTED = "https://01m5c8zg0wkdxjryfxj115bpwy-8080.app.sb.createos.sh/005a10c41b/"

EXTRA = """
.kicker{color:#79c0ff;font-size:30px;letter-spacing:.08em;text-transform:uppercase;margin:0 0 8px}
h1.hero{font-size:78px;line-height:1.1;margin:10px 0 18px}
.row{display:flex;gap:26px;margin:22px 0}.tile{flex:1;background:#161b22;border:1px solid #30363d;border-radius:16px;padding:22px 28px}
.tile h3{margin:0 0 8px;font-size:34px;color:#fff}.tile p{margin:0;font-size:26px;color:#c9d1d9}.tile .y{color:#e3b341;font-weight:700}
.cos{display:inline-block;background:#1565c0;color:#fff;border-radius:8px;padding:2px 12px;font-size:22px;font-weight:700;margin:8px 8px 0 0}
.num{display:inline-block;background:#238636;color:#fff;border-radius:50%;width:46px;height:46px;line-height:46px;text-align:center;font-weight:700;margin-right:12px}
.big2{font-size:64px;font-weight:800}.red{color:#ff7b72}.grn{color:#56d364}.blu{color:#79c0ff}.mut{color:#8b949e;font-size:26px}
.step{flex:1;background:#161b22;border:1px solid #30363d;border-top:6px solid #1565c0;border-radius:14px;padding:18px 20px}
.step h3{margin:0 0 6px;font-size:30px;color:#fff}.step p{margin:0;font-size:23px;color:#c9d1d9;line-height:1.35}
table.k td{font-size:26px}
"""


def _content_png(png):
    """Crop a screenshot to its content, then centre it on a 1920x1080 canvas; return the content height."""
    from PIL import Image, ImageChops

    img = Image.open(png).convert("RGB")
    bg = img.getpixel((5, img.height - 5))
    box = ImageChops.difference(img, Image.new("RGB", img.size, bg)).getbbox() or (0, 0, mc.W, mc.H)
    content = img.crop((0, max(0, box[1] - 30), mc.W, min(img.height, box[3] + 30)))
    canvas = Image.new("RGB", (mc.W, mc.H), bg)
    canvas.paste(content.crop((0, 0, mc.W, min(content.height, mc.H))), (0, max(0, (mc.H - content.height) // 2)))
    canvas.save(png)
    return content.height


def card(name, body, seconds, zoom=1.45):
    """Render an HTML card; shrink the zoom until the content fits on one 1080p screen, then centre it."""
    OUT.mkdir(parents=True, exist_ok=True)
    page = OUT / f"{name}.html"
    png = OUT / f"{name}.png"
    while True:
        page.write_text(mc.page(f"<style>{EXTRA}body{{zoom:{zoom:.2f}}}</style>{body}"), encoding="utf-8")
        mc.screenshot(page.as_uri(), png, height=2600)
        if _content_png(png) <= mc.H - 40 or zoom <= 0.9:
            break
        zoom -= 0.05
    clip = OUT / f"{name}.mp4"
    mc.still_clip(png, clip, seconds)
    return clip


def zoomed_shot(url, png, css_width=1100, height=9000):
    """Screenshot a narrow page at a device scale that makes it 1920 px wide, so its text is large enough to read in a video."""
    from PIL import Image, ImageChops

    scale = mc.W / css_width
    subprocess.run([mc.EDGE, "--headless=new", "--disable-gpu", "--hide-scrollbars", f"--force-device-scale-factor={scale:.4f}",
                    f"--window-size={css_width},{height}", f"--screenshot={png}", url], capture_output=True, timeout=120)
    img = Image.open(png).convert("RGB")
    bg = img.getpixel((5, img.height - 5))
    box = ImageChops.difference(img, Image.new("RGB", img.size, bg)).getbbox()
    img.crop((0, 0, mc.W, max(min(img.height, (box[3] if box else img.height) + 80), mc.H - 70))).save(png)


def build_cards():
    c = {}
    c["title"] = card("c_title", """
<div style="margin-top:210px"><p class=kicker>A recorded run of the real application</p>
<h1 class=hero>Sandtrap</h1>
<p style="font-size:46px;margin:0;color:#c9d1d9">An AI analyst that catches malware that plays dead.</p>
<p class=mut style="margin-top:40px">Built on <span class=cos>CreateOS Sandbox</span> <span class=cos>Stripe Projects</span></p></div>""", 6)
    c["incidents"] = card("c_incidents", """
<p class=kicker>The problem is real</p><h1>Different attacks. One trick.</h1>
<div class=row><div class=tile><h3>Codecov &middot; 2021</h3><p>A tampered CI script sent customers' environment variables to an attacker for about two months.</p></div>
<div class=tile><h3>ctx on PyPI &middot; 2022</h3><p>A hijacked package base64-encoded every environment variable and sent it to the attacker's server.</p></div></div>
<div class=row><div class=tile><h3>event-stream &middot; 2018</h3><p>A payload that only decrypted inside one target app. Nearly 8 million downloads reported.</p></div>
<div class=tile><h3>XZ Utils &middot; 2024</h3><p>A backdoor that only woke up when specific environment checks passed. Found by a CPU anomaly.</p></div></div>
<p class=big2 style="margin-top:26px"><span class=blu>Behave only when the environment looks real.</span></p>
<p class=mut>Sources for each incident: docs/USE-CASES.md</p>""", 15)
    c["problem"] = card("c_problem", """
<p class=kicker>Why normal sandboxes miss it</p><h1>Run it once, see nothing, call it &ldquo;clean&rdquo;</h1>
<div class=row><div class=tile><h3>A normal sandbox</h3><p>Runs the code once, in a plain environment.<br>Sees nothing. Says <span class=grn style="font-weight:700">clean</span>.</p></div>
<div class=tile><h3>Evasive malware asks first</h3><p>Is a <span class=y>CI variable</span> set?<br>Does this <span class=y>domain resolve</span>?<br>What is the <span class=y>date</span>?<br>Is someone <span class=y>tracing</span> me?</p></div></div>
<p class=big2><span class=red>If the answers look wrong, it stays quiet.</span></p>""", 11)
    c["how"] = card("c_how", """
<p class=kicker>What Sandtrap does</p><h1>It acts like a human malware analyst, with an AI doing the legwork</h1>
<div class=row>
<div class=step><h3><span class=num>1</span>Install</h3><p>In a fresh sandbox. Only package registries reachable.</p><span class=cos>microVM</span><span class=cos>files + command API</span></div>
<div class=step><h3><span class=num>2</span>Seal</h3><p>One call blocks every outbound connection.</p><span class=cos>egress control</span></div>
<div class=step><h3><span class=num>3</span>Watch</h3><p>Baseline run. Evasive code stays quiet.</p><span class=cos>strace as root</span></div></div>
<div class=row>
<div class=step><h3><span class=num>4</span>Change the world</h3><p>The AI reads the code, guesses the trigger, builds a fake internet, fake clock, CI variables.</p><span class=cos>iptables</span><span class=cos>date -s</span><span class=cos>pause + fork</span></div>
<div class=step><h3><span class=num>5</span>Prove it</h3><p>Fake credentials with unique tokens. If the code sends them, we catch them.</p><span class=cos>inside the VM</span></div>
<div class=step><h3><span class=num>6</span>Fix and verify</h3><p>Patch it, re-run the same attack, run a smoke test. The verdict comes from code, not the AI.</p><span class=cos>same sandbox</span></div></div>
<p class=mut>Every scan runs in its own disposable CreateOS sandbox, destroyed afterwards.</p>""", 17)
    c["ways"] = card("c_ways", """
<p class=kicker>One engine, many doors</p><h1>Use it where you already work</h1>
<div class=row><div class=tile><h3>Command line</h3><p>scan pypi:requests<br>Python, npm, shell scripts, C binaries.</p></div>
<div class=tile><h3>HTTP API</h3><p>Live progress streaming. Plug it into CI and block risky updates.</p></div></div>
<div class=row><div class=tile><h3>MCP tool</h3><p>AI coding agents ask Sandtrap <i>before</i> they install a package.</p></div>
<div class=tile><h3>Email</h3><p>Email a package name to the agent's inbox. Get the verdict and a report link back.</p></div></div>
<p class=mut>Shown in the recorded demo: docs/proof/demo/ (MCP and email runs).</p>""", 13)
    c["createos"] = card("c_createos", """
<p class=kicker>Why CreateOS Sandbox</p><h1>Sandtrap only works because of these</h1>
<table class=k><tr><th>CreateOS feature</th><th>What Sandtrap does with it</th></tr>
<tr><td><b>Disposable microVMs</b></td><td>One fresh sandbox per scan, destroyed afterwards. Hostile code never survives a scan.</td></tr>
<tr><td><b>Own kernel, real root</b></td><td>strace, iptables, a changeable clock and gcc all work inside the VM.</td></tr>
<tr><td><b>Live egress control</b></td><td>Registry-only, then blocked completely. Every change is read back into the report.</td></tr>
<tr><td><b>Pause + fork</b></td><td>Clone a prepared sandbox three times and test three guesses at once.</td></tr>
<tr><td><b>Public URL (ingress)</b></td><td>A second sandbox serves each report on a public link.</td></tr>
<tr><td><b>Command + files API</b></td><td>The agent's hands: install, run, read, patch, re-run.</td></tr></table>
<p style="margin-top:20px">Provisioned with <b>Stripe Projects</b>: <span class=cos>CreateOS</span><span class=cos>Neon Postgres</span><span class=cos>AgentMail</span> <span class=mut>all on free plans</span></p>""", 15)
    c["safety"] = card("c_safety", """
<p class=kicker>Straight talk</p><h1>Safe by design, honest about limits</h1>
<div class=row><div class=tile><h3 class=grn>Safe by design</h3><p>Samples are harmless fixtures we wrote.<br>The real internet is blocked.<br>Credentials are fake, with unique tokens.<br>The verdict is computed by code.<br>Sandboxes are always destroyed.</p></div>
<div class=tile><h3 class=y>Honest limits</h3><p>Fixtures are simulations of reported behaviour, not live malware.<br>HTTPS bodies are unreadable.<br>Installers that download code are flagged.<br>Samples that detect tracing can hide.</p></div></div>""", 12)
    c["close"] = card("c_close", """
<div style="margin-top:170px"><h1 class=hero>Sandtrap</h1>
<p style="font-size:44px;margin:0;color:#c9d1d9">Make evasive code show itself. Prove it. Fix it.</p>
<p style="font-size:38px;margin-top:40px" class=blu>github.com/hatif03/createos-stripe-hackathon</p>
<p class=mut style="margin-top:28px">Open source (MIT) &middot; 88 tests &middot; Built on <span class=cos>CreateOS Sandbox</span> and <span class=cos>Stripe Projects</span></p></div>""", 9)
    return c


def build_scrolls():
    OUT.mkdir(parents=True, exist_ok=True)
    s = {}
    for name, src, cap, secs, lead in [
        ("report", HOSTED, "Public report served by a CreateOS sandbox (ingress), on a public URL", 18, 1.2),
        ("benchmark", (DEMO.parent / "benchmark.html").as_uri(), "Benchmark: the same 14 samples, scored two ways", 15, 0.8),
        ("realworld", (DEMO.parent / "real-world.html").as_uri(), "Real software, scanned exactly as published", 12, 0.8),
    ]:
        png = OUT / f"s_{name}.png"
        if name == "report":
            zoomed_shot(src, png)
        else:
            mc.screenshot(src, png)
        clip = OUT / f"s_{name}.mp4"
        mc.scroll_clip(png, clip, secs, cap, lead=lead)
        s[name] = clip
    return s


def dur(p):
    return float(subprocess.run(["ffprobe", "-v", "error", "-show_entries", "format=duration", "-of", "csv=p=0", str(p)], capture_output=True, text=True).stdout)


def main():
    mc.build_pages()  # refresh media/benchmark.html and real-world.html from docs/proof
    cards = build_cards()
    scrolls = build_scrolls()
    parts = [
        ("title", "Title", cards["title"]),
        ("incidents", "Real incidents", cards["incidents"]),
        ("problem", "Why normal sandboxes miss it", cards["problem"]),
        ("how", "How Sandtrap works (CreateOS at every step)", cards["how"]),
        ("hero", "Run 1: Python package with an environment-gated stealer (scan, proof, patch)", DEMO / "hero.mp4"),
        ("report", "The public report hosted by a CreateOS sandbox", scrolls["report"]),
        ("elf", "Run 2: a compiled C binary (built and analysed inside the sandbox, with capa)", DEMO / "elf.mp4"),
        ("race", "Fork-and-race: pause, fork three sandboxes, test three guesses at once", DEMO / "race.mp4"),
        ("ways", "Where you can use it (CLI, API, MCP, email)", cards["ways"]),
        ("benchmark", "Benchmark: 12 of 12 vs 4 of 12", scrolls["benchmark"]),
        ("realworld", "Real software: packages clean, installers flagged", scrolls["realworld"]),
        ("createos", "Why CreateOS Sandbox", cards["createos"]),
        ("safety", "Safe by design, honest limits", cards["safety"]),
        ("close", "Close", cards["close"]),
    ]
    lst = OUT / "_concat.txt"
    lst.write_text("".join(f"file '{p.as_posix()}'\n" for _, _, p in parts), encoding="utf-8")
    mc.ffmpeg("-f", "concat", "-safe", 0, "-i", lst, "-c:v", "libx264", "-crf", 20, "-pix_fmt", "yuv420p", OUT / "sandtrap-pitch.mp4")
    t, timeline = 0.0, []
    for key, label, p in parts:
        d = dur(p)
        timeline.append({"key": key, "label": label, "start": round(t, 1), "length": round(d, 1)})
        t += d
    (OUT / "timeline.json").write_text(json.dumps(timeline, indent=2), encoding="utf-8")
    print(f"wrote {OUT / 'sandtrap-pitch.mp4'} ({t:.0f} s)")
    for x in timeline:
        print(f"{int(x['start'] // 60)}:{int(x['start'] % 60):02d}  {x['length']:5.1f}s  {x['label']}")


if __name__ == "__main__":
    sys.exit(main())
