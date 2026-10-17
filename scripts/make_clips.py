"""Render silent B-roll for the demo video from real outputs (hackathon-built).

Needs: system Python with Pillow + markdown, ffmpeg on PATH, Microsoft Edge. Output goes to media/ (gitignored).
  python scripts/make_clips.py capture    # run a real scan, record its terminal output with timestamps
  python scripts/make_clips.py render     # build every clip from the capture, docs/proof/ and the README
  python scripts/make_clips.py master     # stitch clips + placeholder slates into one 2:55 timeline
Timeline and voice-over script: docs/VIDEO-TIMELINE.md
"""
import html
import json
import os
import re
import subprocess
import sys
import time
from pathlib import Path

import markdown
from PIL import Image, ImageChops, ImageDraw, ImageFont

ROOT = Path(__file__).resolve().parents[1]
MEDIA = ROOT / "media"
PROOF = ROOT / "docs" / "proof"
EDGE = r"C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe"
W, H, FPS = 1920, 1080, 30
BG = (13, 17, 23)
CAPTURE = MEDIA / "scan-capture.jsonl"
MONO = "C:/Windows/Fonts/consola.ttf"
MONOB = "C:/Windows/Fonts/consolab.ttf"
SANS = "C:/Windows/Fonts/segoeui.ttf"

# (name, seconds, who) in timeline order; durations add up to 175 s = 2:55
SEGMENTS = [
    ("face-intro", 14, "you"), ("incidents", 6, "me"), ("stack", 25, "me"), ("live-scan", 65, "me"),
    ("public-report", 20, "me"), ("real-world", 10, "me"), ("benchmark", 8, "me"), ("langfuse", 7, "you"),
    ("elf-report", 15, "me"), ("face-outro", 5, "you"),
]


def ffmpeg(*args):
    r = subprocess.run(["ffmpeg", "-y", "-loglevel", "error", *map(str, args)], capture_output=True, text=True)
    if r.returncode:
        sys.exit(f"ffmpeg failed: {r.stderr[-800:]}")


# ---------------------------------------------------------------------------------------------------------------- capture
def capture(target="fixtures/gated-stealer"):
    MEDIA.mkdir(exist_ok=True)
    subprocess.run(["uv", "run", "python", "-m", "src.cli.sandtrap", "gc", "--all"], cwd=ROOT, capture_output=True)
    env = {**os.environ, "FORCE_COLOR": "1", "TERM": "xterm-256color", "COLORTERM": "truecolor", "COLUMNS": "130",
           "LOG_LEVEL": "WARNING", "PYTHONUNBUFFERED": "1", "PYTHONUTF8": "1"}
    p = subprocess.Popen(["uv", "run", "python", "-u", "-m", "src.cli.sandtrap", "scan", target, "--publish", "--out", "out/clips"],
                         cwd=ROOT, env=env, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    t0 = time.perf_counter()
    with CAPTURE.open("w", encoding="utf-8") as f:
        for raw in iter(p.stdout.readline, b""):
            f.write(json.dumps({"t": round(time.perf_counter() - t0, 2), "text": raw.decode("utf-8", "replace")}) + "\n")
            f.flush()
    p.wait()
    print("captured", CAPTURE, "in", round(time.perf_counter() - t0), "s, exit", p.returncode)


ANSI = re.compile(r"\x1b\[([0-9;]*)m")
CSI_OTHER = re.compile(r"\x1b\[[0-9;?]*[A-LN-Za-ln-z]")
LOGLINE = re.compile(r"^\S+Z \[(info|debug|warning|error)\s*\]")
BASIC = [(0, 0, 0), (205, 49, 49), (13, 188, 121), (229, 229, 16), (36, 114, 200), (188, 63, 188), (17, 168, 205), (229, 229, 229),
         (102, 102, 102), (241, 76, 76), (35, 209, 139), (245, 245, 67), (59, 142, 234), (214, 112, 214), (41, 184, 219), (255, 255, 255)]
FG = (204, 204, 204)


def palette(n):
    if n < 16:
        return BASIC[n]
    if n >= 232:
        v = 8 + (n - 232) * 10
        return (v, v, v)
    n -= 16
    lv = [0, 95, 135, 175, 215, 255]
    return (lv[n // 36], lv[(n // 6) % 6], lv[n % 6])


def parse_ansi(text, state):
    """Return a list of (char, fg, bold, dim) for text, updating the SGR state (fg, bold, dim)."""
    out, pos = [], 0
    text = CSI_OTHER.sub("", text)
    for m in ANSI.finditer(text):
        out += [(c, *state) for c in text[pos:m.start()]]
        pos = m.end()
        codes = [int(x) if x else 0 for x in m.group(1).split(";")]
        i = 0
        while i < len(codes):
            c = codes[i]
            if c == 0:
                state[:] = [FG, False, False]
            elif c == 1:
                state[1] = True
            elif c == 2:
                state[2] = True
            elif c in (22,):
                state[1] = state[2] = False
            elif 30 <= c <= 37:
                state[0] = BASIC[c - 30]
            elif 90 <= c <= 97:
                state[0] = BASIC[c - 90 + 8]
            elif c == 39:
                state[0] = FG
            elif c in (38, 48) and i + 1 < len(codes):
                if codes[i + 1] == 5 and i + 2 < len(codes):
                    if c == 38:
                        state[0] = palette(codes[i + 2])
                    i += 2
                elif codes[i + 1] == 2 and i + 4 < len(codes):
                    if c == 38:
                        state[0] = tuple(codes[i + 2:i + 5])
                    i += 4
            i += 1
    out += [(c, *state) for c in text[pos:]]
    return out


class Terminal:
    FONT = 24
    LH = 30
    PAD = 28
    BAR = 44

    def __init__(self, title="sandtrap"):
        self.font = ImageFont.truetype(MONO, self.FONT)
        self.fontb = ImageFont.truetype(MONOB, self.FONT)
        self.cw = self.font.getlength("M")
        self.rows = (H - self.BAR - 2 * self.PAD) // self.LH
        self.lines, self.cur, self.state, self.title = [], [], [FG, False, False], title

    def feed(self, text):
        for ch, *style in parse_ansi(text, self.state):
            if ch == "\n":
                self.lines.append(self.cur)
                self.cur = []
            elif ch == "\r":
                continue
            else:
                self.cur.append((ch, *style))
        self.lines = self.lines[-(self.rows * 4):]

    def frame(self):
        img = Image.new("RGB", (W, H), BG)
        d = ImageDraw.Draw(img)
        d.rectangle([0, 0, W, self.BAR], fill=(30, 36, 44))
        for n, col in enumerate([(255, 95, 86), (255, 189, 46), (39, 201, 63)]):
            d.ellipse([22 + n * 30, 14, 40 + n * 30, 32], fill=col)
        d.text((130, 9), self.title, font=ImageFont.truetype(SANS, 24), fill=(160, 168, 178))
        view = (self.lines + [self.cur])[-self.rows:]
        y = self.BAR + self.PAD
        for line in view:
            x = self.PAD
            for ch, fg, bold, dim in line:
                col = tuple(int(c * 0.6) for c in fg) if dim else fg
                d.text((x, y), ch, font=self.fontb if bold else self.font, fill=col)
                x += self.cw
            y += self.LH
        return img


def render_terminal(events, out, seconds, hold=2.5, title="sandtrap", scale=None):
    """events: [(t, text)] real timestamps; they are scaled to fit `seconds` (minus the hold on the final screen)."""
    total = max(e[0] for e in events) or 1
    scale = scale or (seconds - hold) / total
    term = Terminal(title)
    proc = subprocess.Popen(["ffmpeg", "-y", "-loglevel", "error", "-f", "rawvideo", "-pix_fmt", "rgb24", "-s", f"{W}x{H}", "-r", str(FPS),
                             "-i", "-", "-c:v", "libx264", "-pix_fmt", "yuv420p", "-crf", "20", str(out)], stdin=subprocess.PIPE)
    written = 0

    def emit(frames_until):
        nonlocal written
        raw = term.frame().tobytes()
        while written < frames_until:
            proc.stdin.write(raw)
            written += 1

    for t, text in events:
        emit(int(t * scale * FPS))
        term.feed(text)
    emit(int(seconds * FPS))
    proc.stdin.close()
    proc.wait()


def compress(events, max_gap):
    """Shorten idle waits (sandbox start-up, model latency) so a replay shows the sequence, not the dead air."""
    out, shift, prev = [], 0.0, 0.0
    for t, text in events:
        shift += max(0.0, (t - prev) - max_gap)
        prev = t
        out.append((t - shift, text))
    return out


def typed(command, t0, cps=18):
    """Events that type a shell command one character at a time."""
    prompt = "\x1b[32mPS D:\\createos-stripe-hackathon>\x1b[0m "
    ev = [(t0, prompt)]
    for n, ch in enumerate(command):
        ev.append((t0 + 0.4 + n / cps, ch))
    return ev, t0 + 0.4 + len(command) / cps + 0.3


# ---------------------------------------------------------------------------------------------------------------- html pages
CSS = """
body{margin:0;background:#0d1117;color:#e6edf3;font-family:'Segoe UI',Arial,sans-serif;font-size:30px;line-height:1.45;padding:36px 70px}
h1{font-size:54px;margin:0 0 18px;color:#fff} h2{font-size:42px;margin:30px 0 12px;color:#fff}
table{border-collapse:collapse;width:100%;margin:12px 0;font-size:25px} th,td{border:1px solid #30363d;padding:10px 14px;text-align:left;vertical-align:top}
th{background:#161b22;color:#8b949e;font-weight:600} code{background:#161b22;padding:2px 8px;border-radius:5px;font-family:Consolas,monospace;color:#79c0ff}
a{color:#58a6ff;text-decoration:none} .bad{color:#ff7b72;font-weight:700}.good{color:#56d364;font-weight:700}.mid{color:#e3b341;font-weight:700}
.big{display:flex;gap:40px;margin:24px 0}.card{flex:1;background:#161b22;border:1px solid #30363d;border-radius:14px;padding:26px 34px}
.card b{display:block;font-size:90px;line-height:1.05}.sub{color:#8b949e;font-size:27px}
"""


def page(body):
    return f"<!doctype html><meta charset=utf-8><style>{CSS}</style>{body}"


def verdict_cls(v):
    return {"malicious": "bad", "clean": "good"}.get(v, "mid")


def build_pages():
    bench = json.loads((PROOF / "bench.json").read_text())
    mal = [r for r in bench if r["expected"] == "malicious"]
    agent = sum(r["sandtrap"] == "malicious" for r in mal)
    plain = sum(r["plain"] == "malicious" for r in mal)
    rows = "".join(f"<tr><td><code>{r['fixture']}</code></td><td>{r['expected']}</td><td class={verdict_cls(r['plain'])}>{r['plain']}</td>"
                   f"<td class={verdict_cls(r['sandtrap'])}>{r['sandtrap']}</td><td>{r.get('proof', '-')}</td><td>{r['seconds']} s</td></tr>" for r in bench)
    (MEDIA / "benchmark.html").write_text(page(
        f"<h1>Same run, scored two ways</h1><div class=big><div class=card><span class=sub>A plain sandbox (install + one run)</span><b class=bad>{plain}/{len(mal)}</b>"
        f"<span class=sub>malicious samples detected</span></div><div class=card><span class=sub>Sandtrap (agent changes the environment)</span><b class=good>{agent}/{len(mal)}</b>"
        f"<span class=sub>malicious samples detected, clean fixtures stay clean</span></div></div>"
        f"<table style='font-size:21px'><tr><th>fixture</th><th>expected</th><th>plain sandbox</th><th>sandtrap</th><th>proof</th><th>time</th></tr>{rows}</table>"), encoding="utf-8")
    real = json.loads((PROOF / "real-world.json").read_text())
    rrows = "".join(f"<tr><td><code>{x['kind']}:{html.escape(x['spec'].split('/')[-1])}</code></td><td>{html.escape(x['why'])}</td>"
                    f"<td class={verdict_cls(x['verdict'])}>{x['verdict']}</td><td>{x.get('seconds', '-')} s</td></tr>" for x in real)
    (MEDIA / "real-world.html").write_text(page(
        f"<h1>Real software, not our fixtures</h1><p class=sub>Public packages and installers scanned exactly as published.</p>"
        f"<table><tr><th>target</th><th>why this one</th><th>verdict</th><th>time</th></tr>{rrows}</table>"), encoding="utf-8")
    readme = (ROOT / "README.md").read_text(encoding="utf-8")
    start = readme.index("## Real incidents this is aimed at")
    end = readme.index("**Where it would not have helped")
    body = markdown.markdown(readme[start:end], extensions=["tables"]).replace("<h2>", "<h1>").replace("</h2>", "</h1>")
    (MEDIA / "incidents.html").write_text(page(body.replace("<table>", "<table style='font-size:22px'>")), encoding="utf-8")


def screenshot(url, out_png, height=9000):
    subprocess.run([EDGE, "--headless=new", "--disable-gpu", "--hide-scrollbars", "--force-device-scale-factor=1",
                    f"--window-size={W},{height}", f"--screenshot={out_png}", url], capture_output=True, timeout=120)
    img = Image.open(out_png).convert("RGB")
    bg = img.getpixel((5, img.height - 5))
    box = ImageChops.difference(img, Image.new("RGB", img.size, bg)).getbbox()
    bottom = min(img.height, (box[3] if box else img.height) + 60)
    img.crop((0, 0, W, max(bottom, H - 70))).save(out_png)
    return bg


def banner(text, out_png):
    img = Image.new("RGB", (W, 70), (22, 27, 34))
    ImageDraw.Draw(img).text((40, 14), text, font=ImageFont.truetype(SANS, 34), fill=(230, 237, 243))
    img.save(out_png)


def scroll_clip(png, out, seconds, caption, lead=1.2):
    img = Image.open(png).convert("RGB")
    if img.height < H - 70:
        pad = Image.new("RGB", (W, H - 70), img.getpixel((5, img.height - 1)))
        pad.paste(img, (0, 0))
        img = pad
        img.save(png)
    b = MEDIA / "_banner.png"
    banner(caption, b)
    dd = seconds - 2 * lead
    p = f"clip((t-{lead})/{dd},0,1)"
    y = f"(ih-{H - 70})*(3*pow({p},2)-2*pow({p},3))"
    ffmpeg("-loop", 1, "-framerate", FPS, "-t", seconds, "-i", png, "-loop", 1, "-framerate", FPS, "-t", seconds, "-i", b,
           "-filter_complex", f"[0:v]crop={W}:{H - 70}:0:'{y}'[a];color=c=0x0d1117:s={W}x{H}:r={FPS}[bg];[bg][a]overlay=0:70[c];[c][1:v]overlay=0:0,"
           f"fade=t=in:st=0:d=0.4,fade=t=out:st={seconds - 0.4}:d=0.4,format=yuv420p", "-t", seconds, "-c:v", "libx264", "-crf", 20, out)


def still_clip(png, out, seconds):
    ffmpeg("-loop", 1, "-framerate", FPS, "-t", seconds, "-i", png, "-vf",
           f"scale={W}:{H}:force_original_aspect_ratio=decrease,pad={W}:{H}:(ow-iw)/2:(oh-ih)/2:color=0x0d1117,fade=t=in:st=0:d=0.4,fade=t=out:st={seconds - 0.4}:d=0.4,format=yuv420p",
           "-t", seconds, "-c:v", "libx264", "-crf", 20, out)


def slate(name, seconds, lines, out):
    img = Image.new("RGB", (W, H), (40, 20, 60))
    d = ImageDraw.Draw(img)
    d.text((100, 120), "YOUR CLIP", font=ImageFont.truetype(SANS, 60), fill=(255, 200, 80))
    d.text((100, 220), name, font=ImageFont.truetype(SANS, 110), fill=(255, 255, 255))
    for n, line in enumerate(lines):
        d.text((100, 420 + n * 62), line, font=ImageFont.truetype(SANS, 44), fill=(220, 220, 235))
    png = MEDIA / f"_slate_{name}.png"
    img.save(png)
    still_clip(png, out, seconds)


def read_capture():
    ev = [json.loads(l) for l in CAPTURE.read_text(encoding="utf-8").splitlines()]
    plain = lambda t: ANSI.sub("", CSI_OTHER.sub("", t))
    keep = [(e["t"], e["text"]) for e in ev
            if not LOGLINE.match(plain(e["text"])) and not plain(e["text"]).startswith(("Loading environment", "Loaded environment"))]
    url = next((m.group(0) for e in ev if "public report" in e["text"] for m in [re.search(r"https://\S+", plain(e["text"]))] if m), "")
    return keep, url


def render():
    MEDIA.mkdir(exist_ok=True)
    build_pages()
    keep, url = read_capture()
    dur = {n: s for n, s, _ in SEGMENTS}
    # live-scan fallback replay: the real scan output, scaled to the slot
    render_terminal(compress(keep, 3.0), MEDIA / "live-scan-replay.mp4", dur["live-scan"], title="sandtrap scan fixtures/gated-stealer --publish  (replay of a real run, idle waits shortened)")
    # stack card: the real `stripe projects status` and `doctor` outputs typed out
    status = (PROOF / "stripe-projects-status.txt").read_text(encoding="utf-8").replace("\r", "")
    ev, t = typed("stripe projects status", 1.0)
    ev.append((t, "\n" + status + "\n"))
    e2, t2 = typed("uv run python -m src.cli.sandtrap doctor", t + 7.0)  # the status table stays up for about 7 s
    ev += e2
    ev.append((t2, "\n" + "\n".join(f"  \x1b[32mOK  \x1b[0m {l[7:]}" if l.strip().startswith("OK") else f"  \x1b[31mFAIL\x1b[0m {l[7:]}"
                                    for l in (PROOF / "doctor.txt").read_text(encoding="utf-8").splitlines()) + "\n"))
    render_terminal(ev, MEDIA / "stack.mp4", dur["stack"], title="Stripe Projects + doctor  (real outputs)", scale=1)
    print("stack cues: status typed 1.0s, status output %.1fs, doctor typed %.1fs, doctor output %.1fs" % (t, t + 7.0, t + 7.0 + 0.4, t2))
    hosted = url or (MEDIA / "scan-capture.jsonl").as_uri()
    for name, src, cap, secs in [
        ("public-report", hosted, f"Public report hosted by a CreateOS sandbox  {url}", dur["public-report"]),
        ("elf-report", (PROOF / "fixture-elf-gated-beacon.html").as_uri(), "Compiled C binary: capa static analysis + canary proof", dur["elf-report"]),
        ("incidents", (MEDIA / "incidents.html").as_uri(), "Real incidents: Codecov, ctx, event-stream, XZ, SUNBURST ...", dur["incidents"]),
    ]:
        png = MEDIA / f"{name}.png"
        screenshot(src, png)
        scroll_clip(png, MEDIA / f"{name}.mp4", secs, cap)
    for name, secs in [("real-world", dur["real-world"]), ("benchmark", dur["benchmark"])]:
        png = MEDIA / f"{name}.png"
        screenshot((MEDIA / f"{name}.html").as_uri(), png)
        scroll_clip(png, MEDIA / f"{name}.mp4", secs, {"real-world": "Real PyPI / npm packages and installers (docs/PROOF.md)",
                                                       "benchmark": "Benchmark: plain sandbox vs Sandtrap (docs/BENCHMARK.md)"}[name], lead=0.8)
    print("clips written to", MEDIA)


def master():
    parts = []
    texts = {
        "face-intro": ["You on camera, then the README incident table plays over your voice.", "Face + voice only (no screen)."],
        "langfuse": ["Screen-record the Langfuse Traces page right after your live scan.", "Hover one trace so the span tree is visible."],
        "face-outro": ["You on camera: one closing sentence."],
    }
    t = 0.0
    for name, secs, who in SEGMENTS:
        out = MEDIA / f"_seg_{name}.mp4"
        if who == "you":
            slate(name, secs, texts[name] + [f"{int(t // 60)}:{int(t % 60):02d} - {int((t + secs) // 60)}:{int((t + secs) % 60):02d}  ({secs} s)"], out)
        else:
            src = MEDIA / ("live-scan-replay.mp4" if name == "live-scan" else f"{name}.mp4")
            ffmpeg("-i", src, "-vf", f"fps={FPS},scale={W}:{H},setsar=1,format=yuv420p", "-t", secs, "-c:v", "libx264", "-crf", 20, out)
        parts.append(out)
        t += secs
    lst = MEDIA / "_concat.txt"
    lst.write_text("".join(f"file '{p.as_posix()}'\n" for p in parts), encoding="utf-8")
    ffmpeg("-f", "concat", "-safe", 0, "-i", lst, "-c:v", "libx264", "-crf", 20, "-pix_fmt", "yuv420p", MEDIA / "master-timeline.mp4")
    print("wrote", MEDIA / "master-timeline.mp4", f"({t:.0f} s)")


if __name__ == "__main__":
    {"capture": capture, "render": render, "master": master}[sys.argv[1]]()
