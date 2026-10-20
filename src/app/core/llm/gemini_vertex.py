"""Gemini on Vertex AI through its OpenAI-compatible endpoint, usable from LangChain ``ChatOpenAI``.

Two things plain ``ChatOpenAI`` cannot do against Gemini 3.x, handled by an httpx transport:

* **Auth**: a short-lived OAuth token from ``gcloud auth print-access-token`` (cached, refreshed before expiry).
* **Thought signatures**: Gemini 3 rejects multi-turn tool calls (HTTP 400) unless each assistant tool call carries
  ``extra_content.google.thought_signature``; LangChain drops that field. We re-inject the signature seen in an earlier
  response when we have it, otherwise Google's documented bypass value ``skip_thought_signature_validator``.
It also prefixes bare model names with ``google/``.
"""

from __future__ import annotations

import json
import subprocess
import threading
import time

import httpx

DUMMY_SIGNATURE = "skip_thought_signature_validator"
TOKEN_TTL_S = 40 * 60


class GcloudToken:
    """Cached access token from the gcloud CLI (or a fixed token from ``GEMINI_ACCESS_TOKEN``)."""

    def __init__(self, account: str = "", static_token: str = "") -> None:
        self._account = account
        self._static = static_token
        self._token = ""
        self._expires = 0.0
        self._lock = threading.Lock()

    def get(self) -> str:
        if self._static:
            return self._static
        with self._lock:
            if self._token and time.time() < self._expires:
                return self._token
            cmd = "gcloud auth print-access-token" + (f" --account {self._account}" if self._account else "")
            out = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=60)
            token = out.stdout.strip()
            if out.returncode != 0 or not token:
                raise RuntimeError(f"gcloud token unavailable: {out.stderr.strip()[:200]}")
            self._token, self._expires = token, time.time() + TOKEN_TTL_S
            return token


def _rewrite(body: bytes, signatures: dict[str, dict]) -> bytes:
    """Prefix the model with ``google/`` and make every assistant tool call carry a thought signature."""
    try:
        data = json.loads(body)
    except ValueError:
        return body
    model = data.get("model")
    if isinstance(model, str) and not model.startswith("google/"):
        data["model"] = f"google/{model}"
    for message in data.get("messages", []):
        for call in message.get("tool_calls") or []:
            if not call.get("extra_content"):
                call["extra_content"] = signatures.get(call.get("id", "")) or {
                    "google": {"thought_signature": DUMMY_SIGNATURE}
                }
    return json.dumps(data).encode()


def _remember(response_body: bytes, signatures: dict[str, dict]) -> None:
    """Store signatures from a non-streaming response so later turns can echo the real ones."""
    try:
        data = json.loads(response_body)
    except ValueError:
        return
    if not isinstance(data, dict):
        return  # Vertex answers some errors (quota, overload) with a JSON array; let the OpenAI client raise and retry instead of crashing here
    for choice in data.get("choices", []):
        for call in (choice.get("message") or {}).get("tool_calls") or []:
            if call.get("id") and call.get("extra_content"):
                signatures[call["id"]] = call["extra_content"]


def _prepare(request: httpx.Request, token: GcloudToken, signatures: dict[str, dict], body: bytes) -> httpx.Request:
    new_body = _rewrite(body, signatures)
    headers = {k: v for k, v in request.headers.items() if k.lower() not in ("content-length", "authorization")}
    headers["authorization"] = f"Bearer {token.get()}"
    return httpx.Request(request.method, request.url, headers=headers, content=new_body, extensions=request.extensions)


class VertexTransport(httpx.BaseTransport):
    """Sync transport."""

    def __init__(self, token: GcloudToken) -> None:
        self._inner = httpx.HTTPTransport()
        self._token = token
        self._signatures: dict[str, dict] = {}

    def handle_request(self, request: httpx.Request) -> httpx.Response:
        response = self._inner.handle_request(_prepare(request, self._token, self._signatures, request.read()))
        if "text/event-stream" not in response.headers.get("content-type", ""):
            response.read()
            _remember(response.content, self._signatures)
        return response


class AsyncVertexTransport(httpx.AsyncBaseTransport):
    """Async transport."""

    def __init__(self, token: GcloudToken) -> None:
        self._inner = httpx.AsyncHTTPTransport()
        self._token = token
        self._signatures: dict[str, dict] = {}

    async def handle_async_request(self, request: httpx.Request) -> httpx.Response:
        body = await request.aread()
        response = await self._inner.handle_async_request(_prepare(request, self._token, self._signatures, body))
        if "text/event-stream" not in response.headers.get("content-type", ""):
            await response.aread()
            _remember(response.content, self._signatures)
        return response


def vertex_openai_base_url(project: str, location: str = "global") -> str:
    host = "aiplatform.googleapis.com" if location == "global" else f"{location}-aiplatform.googleapis.com"
    return f"https://{host}/v1/projects/{project}/locations/{location}/endpoints/openapi"


def vertex_http_clients(token: GcloudToken) -> tuple[httpx.Client, httpx.AsyncClient]:
    """Sync and async httpx clients to hand to ``ChatOpenAI(http_client=..., http_async_client=...)``."""
    timeout = httpx.Timeout(180.0, connect=15.0)
    return (
        httpx.Client(transport=VertexTransport(token), timeout=timeout),
        httpx.AsyncClient(transport=AsyncVertexTransport(token), timeout=timeout),
    )
