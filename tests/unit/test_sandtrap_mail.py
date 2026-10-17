"""Mail intake: target extraction (allow-list), message handling with a mocked AgentMail API and a fake scan."""

import json

import httpx

from src.app.sandtrap.mail import Mailbox, extract_target, handle_message, summarize
from src.app.sandtrap.types import AttackRef, Finding, Report


def test_extract_target_uses_the_allow_list():
    assert extract_target("please scan pypi:requests==2.31.0 thanks") == "pypi:requests==2.31.0"
    assert extract_target("pypi:../../etc/passwd") is None
    assert extract_target("fixture:../x and then pypi:six") == "pypi:six"
    assert extract_target("scan http://evil.example/x.sh") is None
    assert extract_target("") is None


def _report(verdict="malicious"):
    return Report(
        job="abc123", target="pypi:demo", verdict=verdict, confidence="high", score=100, lure_only=["sink_request:x.example"],
        findings=[Finding(id="canary_exfil", title="Canary credentials exfiltrated", severity="high", proof="proof",
                          attack=[AttackRef(id="T1041", name="Exfiltration", url="u")])],
        remediation="patched and verified",
    )


def test_summary_contains_only_structured_fields():
    text = summarize(_report(), "https://example.test/r/")
    assert "MALICIOUS" in text and "T1041" in text and "sink_request:x.example" in text and "https://example.test/r/" in text


def _mailbox(tmp_path, sent):
    def handler(request: httpx.Request) -> httpx.Response:
        path = request.url.path
        if request.method == "POST" and path.endswith("/inboxes"):
            return httpx.Response(200, json={"inbox_id": "ib1", "email": "sandtrap-scan@agentmail.to"})
        if request.method == "GET" and path.endswith("/messages"):
            return httpx.Response(200, json={"messages": [
                {"message_id": "m1", "labels": ["received"], "from": "dev@example.com", "subject": "scan"},
                {"message_id": "m2", "labels": ["sent"], "from": "sandtrap-scan@agentmail.to", "subject": "re"},
            ]})
        if request.method == "GET" and "/messages/m1" in path:
            return httpx.Response(200, json={"message_id": "m1", "subject": "scan", "text": "please check pypi:demo"})
        if request.method == "POST" and path.endswith("/reply"):
            sent.append(json.loads(request.content)["text"])
            return httpx.Response(200, json={"message_id": "r1", "thread_id": "t1"})
        return httpx.Response(404, json={})

    return Mailbox(key="k", state_path=str(tmp_path / "state.json"), client=httpx.Client(transport=httpx.MockTransport(handler)))


def test_handle_message_scans_replies_and_marks_processed(tmp_path):
    sent = []
    box = _mailbox(tmp_path, sent)
    inbound = box.new_messages()
    assert [m["message_id"] for m in inbound] == ["m1"]  # our own sent message is ignored
    reply = handle_message(box, inbound[0], scan_fn=lambda target, **kw: _report(), publish=False)
    assert "MALICIOUS" in reply and sent == [reply]
    assert box.new_messages() == []  # processed once


def test_unscannable_message_gets_a_helpful_reply(tmp_path):
    sent = []
    box = _mailbox(tmp_path, sent)
    item = {"message_id": "m1"}
    box.message = lambda _id: {"subject": "hi", "text": "scan my laptop please"}
    reply = handle_message(box, item, scan_fn=lambda *a, **k: (_ for _ in ()).throw(AssertionError("must not scan")), publish=False)
    assert "pypi:<package>" in reply
