"""The in-sandbox sink must find canary tokens however a sample encodes them."""

import base64
import importlib.util
import json
import urllib.parse
from pathlib import Path

SPEC = importlib.util.spec_from_file_location("sandtrap_sink", Path(__file__).resolve().parents[2] / "analyzer" / "sink.py")
sink = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(sink)

TOKEN = "SNDTRP-1a2b3c4d-AWS"
sink.TOKENS = [TOKEN, "SNDTRP-1a2b3c4d-ENV"]


def b64(text: str) -> str:
    return base64.b64encode(text.encode()).decode()


def test_plain_and_urlencoded():
    assert sink.canaries_in(f"key={TOKEN}") == [TOKEN]
    assert sink.canaries_in(urllib.parse.quote(f"secret {TOKEN} end")) == [TOKEN]


def test_whole_body_base64():
    assert sink.canaries_in(b64(f"AWS_SECRET_ACCESS_KEY={TOKEN}")) == [TOKEN]


def test_base64_embedded_in_a_url_like_the_ctx_package():
    env = json.dumps({"PATH": "/usr/bin", "HOME": "/root", "AWS_SECRET_ACCESS_KEY": TOKEN, "GITHUB_TOKEN": "ghp_SNDTRP-1a2b3c4d-ENV"})
    request = "GET /api/v1/ping?d=" + urllib.parse.quote(b64(env)) + " {}"
    assert sink.canaries_in(request) == sorted([TOKEN, "SNDTRP-1a2b3c4d-ENV"])


def test_base64_embedded_in_json_value():
    body = json.dumps({"host": "ci-runner", "data": b64(f"export X={TOKEN}")})
    assert sink.canaries_in(body) == [TOKEN]


def test_benign_text_has_no_canaries():
    assert sink.canaries_in("hello world, nothing here" + b64("just a harmless value that is long enough")) == []
