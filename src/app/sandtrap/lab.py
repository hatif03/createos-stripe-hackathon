"""The analysis lab inside one sandbox: analyzer scripts, canaries, traced install, traced probes (hackathon-built)."""

from __future__ import annotations

import json
import secrets
import time
from dataclasses import dataclass, field
from pathlib import Path

from src.app.core.common.logging import logger
from src.app.sandtrap.sandbox import REGISTRY_EGRESS, SandboxSession
from src.app.sandtrap.types import Event, Probe, ProbeResult

ANALYZER_DIR = Path(__file__).resolve().parents[3] / "analyzer"
OUT_ROOT = "/root/work/out"
VENV_PY = "/root/work/venv/bin/python"
TOKENS_FILE = "/root/work/canary_tokens.txt"
TRACE_SYSCALLS = "execve,connect,openat,open,unlink,unlinkat,rename,renameat,chmod,fchmodat,nanosleep,clock_nanosleep"

INSTALL_SCRIPT = r"""
set -u
OUT=/root/work/out/install; mkdir -p $OUT
python3 -m venv /root/work/venv >$OUT/venv.log 2>&1
ALLOW=""
for h in pypi.org files.pythonhosted.org registry.npmjs.org; do
  for ip in $(getent ahosts $h | awk '{print $1}' | sort -u); do ALLOW="$ALLOW --allow-ip $ip"; done
done
strace -f -qq -ttt -s 256 -e trace=%(syscalls)s -o $OUT/trace.log \
  /root/work/venv/bin/pip install --no-input --disable-pip-version-check %(target)s >$OUT/stdout 2>$OUT/stderr
echo $? > $OUT/exit
python3 /opt/sandtrap/parse_trace.py --trace $OUT/trace.log --exit $OUT/exit --ignore-prefix /root/work/venv \
  --ignore-prefix /root/.cache --ignore-prefix /root/work/pkg $ALLOW --out $OUT/events.json
echo install-done exit=$(cat $OUT/exit)
"""


@dataclass
class InstallResult:
    ok: bool
    exit_code: int
    stdout: str = ""
    stderr: str = ""
    events: list[Event] = field(default_factory=list)


class Lab:
    """Wraps a ``SandboxSession`` with the Sandtrap analyzer and a per-scan canary token."""

    def __init__(self, session: SandboxSession) -> None:
        self.session = session
        self.token = secrets.token_hex(4)
        self.prepared = False

    # -- setup ---------------------------------------------------------------------------------------------------
    def prepare(self) -> None:
        if self.prepared:
            return
        self.session.put_dir(ANALYZER_DIR, "/opt/sandtrap")
        out = self.session.run(f"chmod +x /opt/sandtrap/*.sh && bash /opt/sandtrap/canaries.sh {self.token}")
        if not out.ok:
            raise RuntimeError(f"canary setup failed: {out.stderr[:300]}")
        self.prepared = True

    @property
    def canary_env(self) -> dict[str, str]:
        """Fake credentials in the environment, as a CI runner would have (an `env` dump must be provable too)."""
        return {
            "AWS_SECRET_ACCESS_KEY": f"SNDTRP-{self.token}-AWS/fake-secret-not-real",
            "GITHUB_TOKEN": f"ghp_SNDTRP-{self.token}-ENV",
            "NPM_TOKEN": f"npm_SNDTRP-{self.token}-NPM",
        }

    @property
    def canary_labels(self) -> list[str]:
        return [f"SNDTRP-{self.token}-{k}" for k in ("SSH", "AWS", "NPM", "ENV")] + [f"AKIASNDTRP{self.token}"]

    # -- install -------------------------------------------------------------------------------------------------
    def install_local(self, local_dir: str | Path) -> InstallResult:
        """Upload a local package directory and ``pip install`` it under strace (registry-only egress)."""
        self.prepare()
        self.session.put_dir(local_dir, "/root/work/pkg")
        return self._install("/root/work/pkg")

    def install_pypi(self, spec: str) -> InstallResult:
        self.prepare()
        return self._install(spec.replace("'", ""))

    def install_c(self, source: str | Path) -> InstallResult:
        """Upload a C source file and compile it inside the sandbox (the binary never exists on the host)."""
        self.prepare()
        source = Path(source)
        self.session.run("mkdir -p /root/work/src /root/work/bin")
        self.session.put(f"/root/work/src/{source.name}", source.read_bytes())
        out = self.session.run(f"cd /root/work/src && gcc -O1 -o /root/work/bin/sample {source.name}")
        return InstallResult(ok=out.ok, exit_code=out.exit_code, stdout=out.stdout, stderr=out.stderr)

    def install_script(self, script: str | Path) -> InstallResult:
        """Upload a shell script (CI helper, curl|bash installer); it runs only inside probes, never at upload."""
        self.prepare()
        script = Path(script)
        self.session.run("mkdir -p /root/work/src")
        self.session.put(f"/root/work/src/{script.name}", script.read_bytes())
        return InstallResult(ok=True, exit_code=0)

    def install_npm(self, local_dir: str | Path) -> InstallResult:
        """Upload an npm package and install it WITHOUT running lifecycle scripts; the analyst runs them under the lure."""
        self.prepare()
        self.session.put_dir(local_dir, "/root/work/pkg")
        out = self.session.run("cd /root/work/pkg && npm install --ignore-scripts --no-audit --no-fund 2>&1 | tail -5", timeout=240)
        return InstallResult(ok=True, exit_code=0, stdout=out.stdout, stderr=out.stderr)

    def _install(self, target: str) -> InstallResult:
        script = self._exports({}) + INSTALL_SCRIPT % {"syscalls": TRACE_SYSCALLS, "target": f"'{target}'"}
        started = time.time()
        out = self.session.run(script, timeout=600)
        events = self._events(f"{OUT_ROOT}/install/events.json", round_no=-1)
        exit_code = int(self.session.get_text(f"{OUT_ROOT}/install/exit", "-1").strip() or -1)
        logger.info("install_done", exit_code=exit_code, seconds=round(time.time() - started, 1), events=len(events))
        return InstallResult(
            ok=exit_code == 0,
            exit_code=exit_code,
            stdout=self.session.get_text(f"{OUT_ROOT}/install/stdout")[-4000:],
            stderr=self.session.get_text(f"{OUT_ROOT}/install/stderr")[-4000:] or out.stderr[-2000:],
            events=events,
        )

    # -- probes --------------------------------------------------------------------------------------------------
    def run_probe(self, probe: Probe) -> ProbeResult:
        """Run one traced experiment and return its parsed events."""
        self.prepare()
        out_dir = f"{OUT_ROOT}/r{probe.round}"
        self.session.run(f"rm -rf {out_dir}; mkdir -p {out_dir}")
        shell = probe.driver_code.lstrip().startswith("#!")  # binaries are driven by a bash script
        driver_file = f"{out_dir}/driver.sh" if shell else f"{out_dir}/driver.py"
        interpreter = "/bin/bash" if shell else VENV_PY
        self.session.put(driver_file, probe.driver_code)
        self.session.put(f"{out_dir}/reply.txt", probe.sink_reply)
        env_lines = self._exports(probe.env)
        script = (
            f"{env_lines}"
            f"bash /opt/sandtrap/run_probe.sh {out_dir} {'lure' if probe.lure else 'observe'} {probe.timeout_s} "
            f"{probe.clock_offset_days} {interpreter} {driver_file} {out_dir}/reply.txt {TOKENS_FILE}"
        )
        started = time.time()
        error = ""
        try:
            out = self.session.run(script, timeout=probe.timeout_s + 90)
            if "probe-done" not in out.stdout:
                error = f"probe did not complete: {out.stderr[-300:] or out.stdout[-300:]}"
        except Exception as exc:  # sandbox/API failure: report as a harness error, never as a verdict
            error = f"{type(exc).__name__}: {exc}"
        events = self._events(f"{out_dir}/events.json", round_no=probe.round)
        meta = self._meta(f"{out_dir}/events.json")
        return ProbeResult(
            probe=probe,
            exit_code=int(meta.get("exit_code", -1)),
            stdout=self.session.get_text(f"{out_dir}/stdout")[-4000:],
            stderr=self.session.get_text(f"{out_dir}/stderr")[-4000:],
            events=events,
            duration_ms=int((time.time() - started) * 1000),
            sandbox_id=self.session.id,
            error=error,
        )

    # -- helpers -------------------------------------------------------------------------------------------------
    def _exports(self, extra: dict[str, str]) -> str:
        """Shell export lines: canary environment first, then the experiment's own variables. The API only accepts
        variables declared at sandbox creation, so everything is exported inside the script."""
        return "".join(f"export {k}={json.dumps(v)}\n" for k, v in {**self.canary_env, **extra}.items())

    def _raw(self, path: str) -> dict:
        text = self.session.get_text(path)
        try:
            return json.loads(text) if text else {}
        except ValueError:
            return {}

    def _events(self, path: str, round_no: int) -> list[Event]:
        return [Event(round=round_no, **e) for e in self._raw(path).get("events", [])]

    def _meta(self, path: str) -> dict:
        return self._raw(path).get("meta", {})


def default_driver(modules: list[str]) -> str:
    """A minimal driver: import each top-level module the package provides and report what happened."""
    return (
        "import importlib, sys, traceback\n"
        f"for name in {modules!r}:\n"
        "    try:\n"
        "        importlib.import_module(name)\n"
        "        print('imported', name)\n"
        "    except Exception:\n"
        "        print('import-error', name); traceback.print_exc()\n"
    )


def script_driver(name: str) -> str:
    """Default driver for shell-script targets: run the script the way a CI job would."""
    return f"#!/bin/bash\ncd /root/work\nbash /root/work/src/{name}\necho \"script exited with $?\"\n"


def npm_driver() -> str:
    """Default driver for npm packages: run the install-time lifecycle scripts the way `npm install` would."""
    return (
        "#!/bin/bash\n"
        "cd /root/work/pkg && npm run --if-present preinstall && npm run --if-present install && npm run --if-present postinstall\n"
        'echo "lifecycle exited with $?"\n'
    )


def binary_driver() -> str:
    """Default driver for compiled targets: just run the binary."""
    return "#!/bin/bash\n/root/work/bin/sample\necho \"binary exited with $?\"\n"


def local_modules(local_dir: str | Path) -> list[str]:
    """Top-level python packages in a local fixture directory (dirs containing __init__.py)."""
    root = Path(local_dir)
    return sorted(p.name for p in root.iterdir() if p.is_dir() and (p / "__init__.py").exists())
