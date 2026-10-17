#!/usr/bin/env python3
"""Turn an strace log + the sink log into Sandtrap events (runs INSIDE the sandbox; stdlib only).

Output JSON: {"events": [{t, pid, kind, data}], "meta": {exit_code, duration, timed_out}}.
Event kinds are documented in src/app/sandtrap/types.py.
"""

import argparse
import json
import os
import re

LINE = re.compile(r"^(?:\[pid\s+)?(\d+)\]?\s+(\d+\.\d+)\s+(\w+)\((.*)\)\s+=\s+(-?\d+|\?)(.*)$")
SENSITIVE = [
    ("/.ssh/", "SSH"), ("/.aws/", "AWS"), ("/.npmrc", "NPM"), ("/work/.env", "ENV"), ("/.env", "ENV"),
    ("/.git-credentials", None), ("/.docker/config.json", None), ("/.kube/config", None), ("/etc/shadow", None),
    ("/.bash_history", None), ("/.netrc", None), ("/.pypirc", None), ("/.config/gcloud", None),
]
PERSISTENCE = ("/.bashrc", "/.profile", "/.bash_profile", "/.zshrc", "/crontab", "/etc/cron", "/var/spool/cron",
               "/.config/systemd", "/etc/systemd", "authorized_keys", "/etc/rc.local", "/etc/profile")
IGNORE_WRITE = ("/proc", "/dev", "/sys", "/tmp", "/var/tmp", "/root/work/out", "/root/.cache", "/run")
SUSPICIOUS_BIN = {"curl", "wget", "nc", "ncat", "netcat", "socat", "scp", "ssh", "ftp", "tftp", "base64", "openssl", "nmap"}
SKIP_EXEC = {"timeout", "strace"}


def quoted(args: str) -> list[str]:
    return re.findall(r'"((?:[^"\\]|\\.)*)"', args)


def sensitive_label(path: str):
    for needle, label in SENSITIVE:
        if needle in path:
            return True, label
    return False, None


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--trace", required=True)
    ap.add_argument("--sink", default="")
    ap.add_argument("--tokens", default="")
    ap.add_argument("--exit", dest="exit_file", default="")
    ap.add_argument("--duration", type=float, default=0.0)
    ap.add_argument("--ignore-prefix", action="append", default=[])
    ap.add_argument("--allow-ip", action="append", default=[])
    ap.add_argument("--out", required=True)
    args = ap.parse_args()

    events: list[dict] = []
    first_ts = None
    exec_seen = 0
    chmodded: set[str] = set()
    ignore = tuple(args.ignore_prefix)
    allow_ips = set(args.allow_ip)

    def add(ts: float, pid: int, kind: str, data: dict) -> None:
        events.append({"t": round(ts - first_ts, 3), "pid": pid, "kind": kind, "data": data})

    if os.path.exists(args.trace):
        for raw in open(args.trace, errors="replace"):
            if "<unfinished" in raw:  # a sleep killed by the timeout never "finishes": still record it (time-bomb hint)
                u = re.match(r"^(?:\[pid\s+)?(\d+)\]?\s+(\d+\.\d+)\s+(?:clock_)?nanosleep\(.*tv_sec=(\d+)", raw)
                if u and int(u.group(3)) >= 30:
                    first_ts = first_ts or float(u.group(2))
                    add(float(u.group(2)), int(u.group(1)), "sleep", {"seconds": float(u.group(3))})
                continue
            if "resumed>" in raw:
                continue
            m = LINE.match(raw.strip())
            if not m:
                continue
            pid, ts, call, argstr, ret, rest = int(m.group(1)), float(m.group(2)), m.group(3), m.group(4), m.group(5), m.group(6)
            first_ts = first_ts or ts
            ok = ret not in ("-1", "?")
            q = quoted(argstr)
            if call == "connect":
                addr = re.search(r'inet_addr\("([^"]+)"\)', argstr) or re.search(r'inet_pton\(AF_INET6, "([^"]+)"', argstr)
                port = re.search(r"sin6?_port=htons\((\d+)\)", argstr)
                if addr and port and not addr.group(1).startswith("127.") and addr.group(1) != "::1" and addr.group(1) not in allow_ips and int(port.group(1)) != 53 and not addr.group(1).startswith("169.254."):
                    add(ts, pid, "net_connect", {"addr": addr.group(1), "port": int(port.group(1)), "blocked": not (ret == "0")})
            elif call == "execve" and ok:
                exec_seen += 1
                argv = q[1:] if len(q) > 1 else q
                exe = os.path.basename(q[0]) if q else ""
                if exe in SKIP_EXEC or exec_seen <= 2:  # our own wrapper chain (timeout, interpreter)
                    continue
                joined = " ".join(argv)
                suspicious = os.path.basename(argv[0]) in SUSPICIOUS_BIN if argv else False
                suspicious = suspicious or bool(re.search(r"(curl|wget)\s|base64\s+-d|\|\s*(ba)?sh\b|nc\s+-e", joined))
                add(ts, pid, "exec", {"argv": argv[:12], "suspicious": suspicious})
                if q and q[0] in chmodded:
                    add(ts, pid, "chmod_exec", {"path": q[0]})
            elif call in ("openat", "open") and ok and q:
                path = q[0] if call == "open" else (q[0] if q[0] != "AT_FDCWD" else (q[1] if len(q) > 1 else ""))
                if not path.startswith("/"):
                    continue
                is_sensitive, label = sensitive_label(path)
                writing = bool(re.search(r"O_(WRONLY|RDWR|APPEND|CREAT|TRUNC)", argstr))
                if writing:
                    if ignore and path.startswith(ignore):
                        continue
                    persistence = any(p in path for p in PERSISTENCE)
                    if persistence or not path.startswith(IGNORE_WRITE):
                        if "__pycache__" not in path and not path.endswith(".pyc"):
                            add(ts, pid, "file_write", {"path": path, "persistence": persistence})
                elif is_sensitive:
                    add(ts, pid, "file_read_sensitive", {"path": path, "canary": label})
            elif call in ("unlink", "unlinkat") and ok and q:
                path = next((p for p in q if p.startswith("/")), "")
                if path and not path.startswith(IGNORE_WRITE) and "__pycache__" not in path and not (ignore and path.startswith(ignore)):
                    add(ts, pid, "file_delete", {"path": path, "self": "/site-packages/" in path or "/root/work/pkg" in path})
            elif call in ("chmod", "fchmodat") and ok and q:
                path = next((p for p in q if p.startswith("/")), "")
                mode = re.search(r"0?([0-7]{3,4})\)?$", argstr.strip().rstrip(")"))
                if path and (mode is None or int(mode.group(1)[-3:], 8) & 0o111):
                    chmodded.add(path)
            elif call in ("nanosleep", "clock_nanosleep"):
                sec = re.search(r"tv_sec=(\d+)", argstr)
                if sec and int(sec.group(1)) >= 30:
                    add(ts, pid, "sleep", {"seconds": float(sec.group(1))})

    first_ts = first_ts or 0.0

    sink_events = 0
    if args.sink and os.path.exists(args.sink):
        for raw in open(args.sink, errors="replace"):
            try:
                rec = json.loads(raw)
            except ValueError:
                continue
            t = float(rec.get("t", 0.0))
            kind = rec.get("type")
            if kind == "dns":
                events.append({"t": t, "pid": 0, "kind": "dns_query", "data": {"name": rec["name"], "answered": bool(rec.get("answered"))}})
            elif kind == "http":
                sink_events += 1
                events.append({"t": t, "pid": 0, "kind": "sink_request", "data": {
                    "host": rec.get("host", ""), "method": rec.get("method", ""), "path": rec.get("path", ""),
                    "body": rec.get("body", "")[:2000], "canaries": rec.get("canaries", []), "orig_dst": rec.get("orig_dst", "")}})
            elif kind == "tls":
                sink_events += 1
                events.append({"t": t, "pid": 0, "kind": "sink_request", "data": {
                    "host": rec.get("sni", "") or rec.get("orig_dst", ""), "method": "TLS", "path": "", "body": "",
                    "canaries": [], "orig_dst": rec.get("orig_dst", "")}})
            elif kind == "tcp" and rec.get("text"):
                sink_events += 1
                events.append({"t": t, "pid": 0, "kind": "sink_request", "data": {
                    "host": rec.get("orig_dst", ""), "method": "TCP", "path": "", "body": rec.get("text", "")[:2000],
                    "canaries": rec.get("canaries", []), "orig_dst": rec.get("orig_dst", "")}})

    exit_code = -1
    if args.exit_file and os.path.exists(args.exit_file):
        try:
            exit_code = int(open(args.exit_file).read().strip() or -1)
        except ValueError:
            exit_code = -1
    timed_out = exit_code in (124, 137)
    behaviour = {"net_connect", "sink_request", "file_read_sensitive", "file_write", "exec", "chmod_exec", "file_delete"}
    if exit_code == 0 and args.duration and args.duration < 4.0 and not any(e["kind"] in behaviour for e in events):
        events.append({"t": args.duration, "pid": 0, "kind": "gate_exit", "data": {"reason": f"exited 0 after {args.duration:.1f}s with no observable behaviour"}})

    events.sort(key=lambda e: e["t"])
    json.dump({"events": events, "meta": {"exit_code": exit_code, "duration": args.duration, "timed_out": timed_out}}, open(args.out, "w"))


if __name__ == "__main__":
    main()
