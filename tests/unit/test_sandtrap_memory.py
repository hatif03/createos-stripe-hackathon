import threading

import pytest

from src.app.sandtrap import memory as memmod
from src.app.sandtrap.memory import Skill, ThreatMemory
from src.app.sandtrap.types import Event, Probe, ProbeResult, Report


@pytest.fixture
def mem(tmp_path):
    return ThreatMemory(tmp_path / "sub" / "m.db")


def rep(job="j1", target="pypi:evil", sha="abc", verdict="malicious", hosts=()):
    evs = [Event(kind="dns_query", data={"name": h, "answered": True}) for h in hosts]
    return Report(job=job, target=target, sha256=sha, verdict=verdict, rounds=[ProbeResult(probe=Probe(), events=evs)])


def test_cache_by_sha(mem):
    assert mem.cached(sha256="abc") is None
    mem.remember_scan(rep(job="a"))
    mem.remember_scan(rep(job="b"))
    assert mem.cached(sha256="abc").job == "b"
    assert mem.cached(sha256="other") is None
    assert mem.cached() is None


def test_no_cache_for_inconclusive(mem):
    mem.remember_scan(rep(verdict="inconclusive"))
    assert mem.cached(sha256="abc") is None
    assert mem.cached(target="pypi:evil") is None


def test_pypi_target_expiry_and_non_pypi(mem, monkeypatch):
    now = 1_000_000.0
    monkeypatch.setattr(memmod.time, "time", lambda: now)
    mem.remember_scan(rep(sha=""))
    mem.remember_scan(rep(job="g", target="github:x/y", sha=""))
    monkeypatch.setattr(memmod.time, "time", lambda: now + 23 * 3600)
    assert mem.cached(target="pypi:evil").job == "j1"
    assert mem.cached(target="github:x/y") is None
    monkeypatch.setattr(memmod.time, "time", lambda: now + 25 * 3600)
    assert mem.cached(target="pypi:evil") is None


def test_ioc_extract_and_upsert(mem):
    r = rep(hosts=["telemetry.cdn-metrics.example", "pypi.org", "files.pythonhosted.org"])
    r.rounds[0].events += [
        Event(kind="sink_request", data={"host": "evil.example:8080"}),
        Event(kind="net_connect", data={"addr": "203.0.113.9", "port": 443}),
        Event(kind="net_connect", data={"addr": "127.0.0.1", "port": 80}),
    ]
    iocs = {i["value"]: i["kind"] for i in mem.extract_iocs(r)}
    assert iocs == {"telemetry.cdn-metrics.example": "domain", "evil.example": "domain", "203.0.113.9": "ip"}
    mem.remember_iocs(r)
    mem.remember_iocs(r)  # same job again: no double count
    mem.remember_iocs(rep(job="j2", verdict="suspicious", hosts=["evil.example"]))
    got = {k["value"]: k for k in mem.known_iocs(["evil.example", "203.0.113.9", "nope"])}
    assert got["evil.example"]["seen_count"] == 2 and got["evil.example"]["last_verdict"] == "suspicious"
    assert got["203.0.113.9"]["seen_count"] == 1
    assert "nope" not in got and mem.known_iocs([]) == []
    assert mem.stats()["iocs"] == 3


def test_annotate_only_other_jobs(mem):
    h = "telemetry.cdn-metrics.example"
    mem.remember_iocs(rep(job="old1", hosts=[h]))
    mem.remember_iocs(rep(job="old2", hosts=[h, "other.example"]))
    cur = rep(job="new", verdict="clean", hosts=[h, "fresh.example"])
    mem.remember_iocs(cur)
    assert mem.annotate(cur) == [f"known indicator {h} (seen in 2 earlier scans, last verdict malicious)"]
    assert mem.annotate(rep(job="old1", hosts=["only-mine.example"])) == []


def test_skills_upsert_and_ranking(mem):
    mem.save_skill(Skill(name="dns-ci-gate", description="gated on DNS resolving and CI env var",
                         signs=["silent exit", "gate_exit"], lure={"lure": True, "env": {"CI": "1"}}))
    mem.save_skill(Skill(name="time-bomb", description="sleeps for days before payload",
                         signs=["long sleep"], lure={"clock_offset_days": 30}))
    mem.record_use("dns-ci-gate", True)
    mem.record_use("dns-ci-gate", False)
    mem.save_skill(Skill(name="dns-ci-gate", description="gated on DNS resolving and CI env var v2",
                         signs=["silent exit"], lure={"lure": True}))
    skills = {s.name: s for s in mem.list_skills()}
    assert len(skills) == 2
    assert skills["dns-ci-gate"].uses == 2 and skills["dns-ci-gate"].successes == 1
    assert skills["dns-ci-gate"].description.endswith("v2")
    text = "silent exit unless domain resolves and CI is set"
    assert mem.relevant_skills(text)[0].name == "dns-ci-gate"
    assert [s.name for s in mem.relevant_skills("sleeps for days", limit=1)] == ["time-bomb"]
    assert mem.relevant_skills("completely unrelated banana") == []


def test_render_prompt(mem):
    assert mem.render_skills_for_prompt([]) == ""
    s = Skill(name="dns-ci-gate", description="gate", signs=["silent exit"], lure={"lure": True, "env": {"CI": "1"}})
    out = mem.render_skills_for_prompt([s])
    assert out.startswith("Skills learned from earlier scans (try these first, but verify):")
    assert "dns-ci-gate" in out and "silent exit" in out and '"CI": "1"' in out


def test_threads(mem):
    def work(i):
        for k in range(10):
            r = rep(job=f"t{i}-{k}", sha=f"s{i}-{k}", hosts=[f"h{k}.example"])
            mem.remember_scan(r)
            mem.remember_iocs(r)
            mem.save_skill(Skill(name=f"s{k}", description="x"))

    ts = [threading.Thread(target=work, args=(i,)) for i in range(6)]
    [t.start() for t in ts]
    [t.join() for t in ts]
    st = mem.stats()
    assert st == {"scans": 60, "iocs": 10, "skills": 10}
    assert mem.known_iocs(["h3.example"])[0]["seen_count"] == 6
