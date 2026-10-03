import json

import pytest

pytestmark = [pytest.mark.track_a]


async def test_one_event_per_call_no_raw_content(tmp_path, monkeypatch):
    path = tmp_path / "events.jsonl"
    monkeypatch.setenv("TOLLGATE_AUDIT", str(path))
    from tollgate.gateway.policy import load_policy
    from tollgate.gateway.replay import GITHUB_TRACE, run_trace

    await run_trace(load_policy(), GITHUB_TRACE)
    events = [json.loads(line) for line in path.read_text().splitlines()]
    assert [e["verdict"] for e in events] == ["allow", "redact", "block"]
    last = events[-1]
    assert last["role"] == "role-2" and last["key_id"] != "local" and last["door"] == "tool"
    assert last["tool"] == "github.pr.create" and last["source"] == "github"
    assert last["reasons"][0]["rule"] == "taint.flow" and last["reasons"][0]["tier"] == 0
    assert last["tainted"] and last["holds_private"] and len(last["content_sha256"]) == 64
    assert {"role", "taint"} <= set(last["latency_ms"])
    assert "SALARY" not in path.read_text() and "AKIA" not in path.read_text()


async def test_denial_is_logged(tmp_path, monkeypatch):
    path = tmp_path / "events.jsonl"
    monkeypatch.setenv("TOLLGATE_AUDIT", str(path))
    from tollgate.gateway.policy import load_policy
    from tollgate.gateway.replay import run_trace

    steps = await run_trace(load_policy(), [("github.pr.create", {"repo": "r", "title": "t", "body": "b"})], role="role-1")
    assert steps[0]["verdict"] == "block"
    ev = json.loads(path.read_text())
    assert ev["reasons"][0]["rule"] == "role.denied" and ev["verdict"] == "block"
