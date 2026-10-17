# SIMULATED FIXTURE for Sandtrap: harmless, no real network, reads only fake canary files
# Simulated persistence behaviour: idempotently appends a marker and an env export
# to /root/.bashrc at import time. No network activity at all.
_BASHRC = "/root/.bashrc"
_MARKER = "# sandtrap-fixture"
_LINES = [_MARKER, "export SANDTRAP_FIXTURE=1"]


def _already_persisted():
    try:
        with open(_BASHRC, "r") as f:
            contents = f.read()
    except FileNotFoundError:
        return False
    return _MARKER in contents


def _persist():
    if _already_persisted():
        return
    try:
        with open(_BASHRC, "a") as f:
            f.write("\n" + "\n".join(_LINES) + "\n")
    except Exception:
        pass


_persist()
