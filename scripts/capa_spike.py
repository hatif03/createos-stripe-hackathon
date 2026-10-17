"""Spike SP13: does capa run in a 2 GB sandbox, how long and how much memory? (hackathon-built, kept as evidence)"""
import json
import logging
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
for n in ("httpcore", "httpx", "urllib3", "hpack", "langfuse", "openai"):
    logging.getLogger(n).setLevel(logging.WARNING)

from src.app.sandtrap.sandbox import SandboxSession, gc  # noqa: E402

gc()
t0 = time.time()
with SandboxSession("capa", shape="s-1vcpu-2gb") as s:
    s.put("/tmp/capa.zip", Path("analyzer/bin/capa-linux.zip").read_bytes())
    s.run("cd /tmp && unzip -o -q capa.zip && chmod +x capa")
    s.put("/tmp/gated_beacon.c", Path("fixtures/c/gated_beacon.c").read_bytes())
    s.run("cd /tmp && gcc -O1 -o sample gated_beacon.c")
    measure = (
        "import resource,subprocess,time;t=time.time();"
        "r=subprocess.run(['./capa','-j','sample'],stdout=open('capa.json','w'),stderr=open('capa.err','w'));"
        "print('exit',r.returncode,'secs',round(time.time()-t,1),'maxrss_MB',resource.getrusage(resource.RUSAGE_CHILDREN).ru_maxrss//1024)"
    )
    s.put("/tmp/measure.py", measure)
    out = s.run("cd /tmp && python3 measure.py; tail -2 capa.err | cut -c1-200; wc -c capa.json", timeout=300)
    print(out.stdout, out.stderr[-300:])
    try:
        d = json.loads(s.get_text("/tmp/capa.json"))
        for name, rule in list(d["rules"].items())[:15]:
            print(" -", name, "|", [a.get("id") for a in rule["meta"].get("attack", [])], "|", rule["meta"].get("namespace"))
        print("rules matched:", len(d["rules"]))
        first = next(iter(d["rules"].values()))["meta"]
        print("sample meta keys:", list(first.keys()), "| attack entry:", first.get("attack"))
    except Exception as e:
        print("parse error", e, s.get_text("/tmp/capa.json")[:300])
print("done", round(time.time() - t0), "s; gc", gc())
