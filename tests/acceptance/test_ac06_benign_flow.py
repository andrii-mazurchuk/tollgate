import pytest

pytestmark = [pytest.mark.track_a]


async def test_ac06_benign_flow(tmp_path, monkeypatch):
    """AC6: Read a public issue, then open a PR with no private read: allowed."""
    monkeypatch.setenv("TOLLGATE_AUDIT", str(tmp_path / "events.jsonl"))
    from tollgate.mocks.github import PRS
    from tollgate.gateway.policy import load_policy
    from tollgate.gateway.replay import run_trace

    PRS.clear()
    trace = [
        ("github.issues.read", {"repo": "acme/website", "number": 12}),
        ("github.pr.create", {"repo": "acme/website", "title": "Fix footer links", "body": "Fixes #12: footer links on mobile."}),
    ]
    steps = await run_trace(load_policy(), trace)
    assert [s["verdict"] for s in steps] == ["allow", "allow"]
    assert PRS[-1]["body"] == "Fixes #12: footer links on mobile."
    PRS.clear()
