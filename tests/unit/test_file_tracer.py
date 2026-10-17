"""Unit tests for FileTracer."""

import json
from pathlib import Path

import pytest

from src.app.core.common import config as config_module
from src.app.core.tracing.file_tracer import FileTracer


@pytest.fixture
def test_settings(monkeypatch):
    monkeypatch.setenv("APP_ENV", "test")
    return config_module.Settings()


def test_file_tracer_writes_json_when_enabled(test_settings, tmp_path):
    test_settings.FILE_TRACING_ENABLED = True
    test_settings.FILE_TRACING_DIR = str(tmp_path)

    tracer = FileTracer(test_settings)
    with tracer.trace_agent_request("test_request", input_data={"query": "hi"}) as root:
        assert root is not None
        span = tracer.create_span(root, "child", input_data={"x": 1})
        tracer.end_span(span, output={"ok": True})
        root.update(output={"answer": "hello"})

    tracer.flush()

    files = list(Path(tmp_path).glob("*.json"))
    assert len(files) == 1
    payload = json.loads(files[0].read_text(encoding="utf-8"))
    assert payload["name"] == "test_request"
    assert payload["output"] == {"answer": "hello"}
    assert len(payload["spans"]) == 1


def test_file_tracer_noop_when_disabled(test_settings, tmp_path):
    test_settings.FILE_TRACING_ENABLED = False
    test_settings.FILE_TRACING_DIR = str(tmp_path)

    tracer = FileTracer(test_settings)
    with tracer.trace_agent_request("test_request") as root:
        assert root is None

    tracer.flush()
    assert list(Path(tmp_path).glob("*.json")) == []
