"""`sandtrap doctor`: verify the whole stack in one command (hackathon-built).

Checks the Stripe Projects state, the CreateOS account/API, the LLM provider, the Neon database provisioned by Stripe Projects,
Langfuse tracing, the capa binary, and leftover sandboxes. Prints values only as OK/FAIL, never secrets.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
from dataclasses import dataclass

from src.app.core.common.config import settings


@dataclass
class Check:
    name: str
    ok: bool
    detail: str


def _stripe_projects() -> Check:
    exe = shutil.which("stripe")
    if not exe:
        return Check("stripe projects", False, "stripe CLI not found")
    try:
        out = subprocess.run([exe, "projects", "status", "--json"], capture_output=True, text=True, timeout=60, shell=os.name == "nt")
        data = json.loads(out.stdout[out.stdout.index("{"):])["data"]
    except Exception as exc:
        return Check("stripe projects", False, f"status failed: {type(exc).__name__}")
    providers = ", ".join(sorted(p["name"] for p in data.get("providers", [])))
    services = ", ".join(sorted(s["name"] for s in data.get("services", []) + data.get("plans", [])))
    return Check("stripe projects", True, f"project {data['project']['name']}; providers: {providers}; resources: {services}")


def _createos() -> Check:
    from src.app.sandtrap.sandbox import make_client

    try:
        me = make_client().who_am_i()
        return Check("createos sandbox api", True, f"{settings.CREATEOS_SANDBOX_BASE_URL} account ok ({getattr(me, 'plan', 'plan n/a')})")
    except Exception as exc:
        return Check("createos sandbox api", False, f"{type(exc).__name__}: {str(exc)[:100]}")


def _llm() -> Check:
    try:
        from src.app.core.llm.factory import make_chat_model

        reply = make_chat_model(f"openai:{settings.LLM_MODEL}", max_tokens=200).invoke("Reply with the single word: ok")
        return Check("llm", True, f"{settings.LLM_PROVIDER}:{settings.LLM_MODEL} answered")
    except Exception as exc:
        return Check("llm", False, f"{type(exc).__name__}: {str(exc)[:100]}")


def _neon() -> Check:
    url = os.getenv("NEON_POSTGRES_CONNECTION_STRING", "").strip().strip("'\"")
    if not url:
        return Check("neon postgres", False, "NEON_POSTGRES_CONNECTION_STRING not set (stripe projects add neon/postgres)")
    try:
        import psycopg

        with psycopg.connect(url, connect_timeout=10) as conn:
            version = conn.execute("select version()").fetchone()[0].split(",")[0]
        return Check("neon postgres", True, f"{version} (LangGraph checkpoints)")
    except Exception as exc:
        return Check("neon postgres", False, f"{type(exc).__name__}: {str(exc)[:100]}")


def _langfuse() -> Check:
    if not (settings.LANGFUSE_PUBLIC_KEY and settings.LANGFUSE_SECRET_KEY):
        return Check("langfuse", False, "no keys: tracing disabled (optional)")
    from src.app.core.tracing.factory import make_langfuse_tracer

    tracer = make_langfuse_tracer(settings)
    return Check("langfuse", bool(tracer.is_enabled), "authenticated" if tracer.is_enabled else "auth failed")


def _capa() -> Check:
    from src.app.static.capa import CAPA_ZIP

    return Check("capa (static layer)", CAPA_ZIP.exists(), f"{CAPA_ZIP.name} {CAPA_ZIP.stat().st_size // 1_000_000} MB" if CAPA_ZIP.exists() else "missing: see README setup")


def _leftovers() -> Check:
    from src.app.sandtrap.sandbox import make_client

    try:
        live = [i for i in make_client().list_sandboxes() if "destroy" not in str(getattr(i.data, "status", "")).lower()
                and not (i.name or "").startswith("sandtrap-rpt")]  # the report host is long-lived on purpose
        return Check("leftover sandboxes", not live, f"{len(live)} live sandbox(es)" + ("" if not live else " (run: sandtrap gc)"))
    except Exception as exc:
        return Check("leftover sandboxes", False, f"{type(exc).__name__}")


def run_doctor() -> list[Check]:
    return [_stripe_projects(), _createos(), _llm(), _neon(), _langfuse(), _capa(), _leftovers()]
