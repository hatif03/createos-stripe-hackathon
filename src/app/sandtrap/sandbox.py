"""CreateOS Sandbox session for Sandtrap (hackathon-built).

One ``SandboxSession`` = one microVM. It always destroys itself (context manager), records every egress-policy change in a
timeline (shown in the report), and can snapshot (pause) and fork. ``gc`` removes anything left behind (names are tagged
``sandtrap-*``) because parallel forks make leaks easy.
"""

from __future__ import annotations

import io
import secrets
import tarfile
import time
from dataclasses import dataclass
from pathlib import Path

from createos import Client, CreateSandboxRequest, ExecOptions, ForkSandboxRequest, RunCommandRequest
from createos.models import ListSandboxesOptions

from src.app.core.common.config import settings
from src.app.core.common.logging import logger
from src.app.sandtrap.types import EgressStep

NAME_PREFIX = "sandtrap-"
REGISTRY_EGRESS = ["pypi.org:443", "files.pythonhosted.org:443", "registry.npmjs.org:443"]
BLOCK_ALL = ["192.0.2.1:9"]  # an empty allowlist means "allow all", so "block everything" is one unroutable TEST-NET rule
OUTPUT_LIMIT = 200_000


@dataclass
class CommandOutput:
    stdout: str
    stderr: str
    exit_code: int
    ms: float = 0.0

    @property
    def ok(self) -> bool:
        return self.exit_code == 0


def make_client() -> Client:
    return Client(settings.CREATEOS_SANDBOX_API_KEY, base_url=settings.CREATEOS_SANDBOX_BASE_URL, timeout=120.0)


class SandboxSession:
    """A single sandbox with guaranteed cleanup."""

    def __init__(
        self,
        label: str = "scan",
        shape: str = "s-1vcpu-2gb",
        rootfs: str = "devbox:1",
        egress: list[str] | None = None,
        client: Client | None = None,
    ) -> None:
        self.client = client or make_client()
        self.label = label
        self.shape = shape
        self.rootfs = rootfs
        self.initial_egress = egress or []
        self.instance = None
        self.egress_timeline: list[EgressStep] = []
        self.related_ids: list[str] = []  # forks created from this sandbox (shown in the report)
        self.destroyed = False

    # -- lifecycle ---------------------------------------------------------------------------------------------
    def __enter__(self) -> "SandboxSession":
        return self.create()

    def __exit__(self, *exc) -> None:
        self.destroy()

    @property
    def id(self) -> str:
        return self.instance.id if self.instance else ""

    def create(self) -> "SandboxSession":
        name = f"{NAME_PREFIX}{self.label[:6]}-{secrets.token_hex(3)}"  # platform limit: 22 characters
        request = CreateSandboxRequest(
            shape=self.shape, rootfs=self.rootfs, name=name, egress_rules=list(self.initial_egress)
        )
        self.instance = self.client.create_sandbox(request)
        self._wait_running()
        self.egress_timeline.append(
            EgressStep(phase="create", rules=self.initial_egress or ["* (all egress allowed)"], note=f"sandbox {self.id}")
        )
        logger.info("sandbox_created", sandbox_id=self.id, name=name, shape=self.shape)
        return self

    def destroy(self) -> None:
        if self.instance is None or self.destroyed:
            return
        try:
            self.instance.destroy()
            self.destroyed = True
            logger.info("sandbox_destroyed", sandbox_id=self.id)
        except Exception:
            logger.warning("sandbox_destroy_failed", sandbox_id=self.id, exc_info=True)

    # -- commands & files --------------------------------------------------------------------------------------
    def run(self, script: str, timeout: float = 120.0, env: dict[str, str] | None = None) -> CommandOutput:
        """Run a shell script (``sh -c``) and return stdout, stderr, exit code."""
        started = time.time()
        response = self.instance.run_command(
            RunCommandRequest(command="sh", arguments=["-c", script], environment_variables=env or {}),
            ExecOptions(timeout=timeout),
        )
        result = response.result
        return CommandOutput(
            stdout=(result.standard_output or "")[-OUTPUT_LIMIT:],
            stderr=(result.standard_error or "")[-OUTPUT_LIMIT:],
            exit_code=result.exit_code if result.exit_code is not None else -1,
            ms=(time.time() - started) * 1000,
        )

    def put(self, path: str, data: bytes | str) -> None:
        self.instance.files.upload(path, data.encode() if isinstance(data, str) else data)

    def get(self, path: str) -> bytes:
        stream = self.instance.files.download(path)
        try:
            return stream.read()
        finally:
            stream.close()

    def get_text(self, path: str, default: str = "") -> str:
        try:
            return self.get(path).decode("utf-8", "replace")
        except Exception:
            return default

    def put_dir(self, local_dir: str | Path, remote_dir: str, exclude: tuple[str, ...] = ("__pycache__", ".git")) -> None:
        """Upload a local directory (tar.gz over the files API, extracted in the sandbox)."""
        local = Path(local_dir)
        buffer = io.BytesIO()
        with tarfile.open(fileobj=buffer, mode="w:gz") as archive:
            for path in sorted(local.rglob("*")):
                if any(part in exclude for part in path.parts):
                    continue
                archive.add(path, arcname=str(path.relative_to(local)).replace("\\", "/"), recursive=False)
        remote_tar = f"/tmp/up-{secrets.token_hex(3)}.tgz"
        self.put(remote_tar, buffer.getvalue())
        out = self.run(f"mkdir -p {remote_dir} && tar xzf {remote_tar} -C {remote_dir} && rm -f {remote_tar}")
        if not out.ok:
            raise RuntimeError(f"upload_dir failed: {out.stderr[:200]}")

    # -- egress ------------------------------------------------------------------------------------------------
    def set_egress(self, rules: list[str], phase: str, note: str = "") -> list[str]:
        """Replace the egress allowlist, record it, and read it back from the platform."""
        self.instance.set_egress(rules)
        active = list(self.instance.egress().egress_rules) if hasattr(self.instance.egress(), "egress_rules") else rules
        self.egress_timeline.append(EgressStep(phase=phase, rules=active or ["* (all egress allowed)"], note=note))
        logger.info("sandbox_egress_set", sandbox_id=self.id, phase=phase, rules=active)
        return active

    def lock_down(self, phase: str = "locked", note: str = "all outbound traffic blocked") -> list[str]:
        return self.set_egress(BLOCK_ALL, phase, note)

    # -- snapshots ---------------------------------------------------------------------------------------------
    def snapshot(self) -> None:
        """Pause the sandbox (disk + memory preserved); resume with ``resume`` or clone with ``fork``."""
        self.instance.pause()
        self.instance.wait_until_paused()

    def resume(self) -> None:
        self.instance.resume()
        self._wait_running()

    def fork(self, label: str = "fork", egress: list[str] | None = None) -> "SandboxSession":
        """Clone this (paused) sandbox into a new running one."""
        child = SandboxSession(label=label, shape=self.shape, rootfs=self.rootfs, client=self.client)
        request = ForkSandboxRequest(egress_rules=egress) if egress is not None else None
        child.instance = self.instance.fork(request)
        child._wait_running()
        child.egress_timeline.append(EgressStep(phase="fork", rules=egress or self.egress_timeline[-1].rules, note=f"fork of {self.id}"))
        logger.info("sandbox_forked", parent=self.id, child=child.id)
        return child

    def _wait_running(self, timeout: float = 120.0) -> None:
        """Wait for a fork to run. Under concurrency the platform may park a child as 'paused': resume it."""
        deadline = time.time() + timeout
        resumes = 0
        while time.time() < deadline:
            status = str(self.instance.refresh().data.status).lower()
            if status.endswith("running"):
                return
            if status.endswith("paused") and resumes < 3:
                resumes += 1
                logger.info("fork_child_parked_resuming", sandbox_id=self.id, attempt=resumes)
                try:
                    self.instance.resume()
                except Exception:
                    logger.warning("fork_child_resume_failed", sandbox_id=self.id, exc_info=True)
            time.sleep(2)
        raise TimeoutError(f"sandbox {self.id} did not reach running within {timeout:.0f}s")

    def preview_url(self, port: int) -> str:
        self.instance.set_ingress(True)
        return self.instance.preview_url(port)


def gc(client: Client | None = None, everything: bool = False) -> int:
    """Destroy leftover sandboxes: ``sandtrap-*`` ones, forks of them (forks get random platform names) or, with
    ``everything=True``, every live sandbox of the account. Returns how many were removed."""
    client = client or make_client()
    live = [i for i in client.list_sandboxes(ListSandboxesOptions()) if "destroy" not in str(getattr(i.data, "status", "")).lower()]
    ours = {i.id for i in live if (i.name or "").startswith(NAME_PREFIX) and not (i.name or "").startswith(NAME_PREFIX + "rpt")}
    removed = 0
    for instance in live:
        parent = getattr(instance.data, "forked_from", None) or ""
        if everything or instance.id in ours or parent in ours:
            try:
                instance.destroy()
                removed += 1
            except Exception:
                logger.warning("gc_destroy_failed", sandbox_id=instance.id, exc_info=True)
    return removed
