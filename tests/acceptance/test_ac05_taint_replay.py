import copy

import pytest

pytestmark = [pytest.mark.track_a]


async def test_ac05_taint_replay(tmp_path, monkeypatch):
    """AC5: GitHub attack trace leaks with taint disabled and is blocked with the named cause with taint enabled."""
    monkeypatch.setenv("TOLLGATE_AUDIT", str(tmp_path / "events.jsonl"))
    from tollgate.mocks.github import PRS
    from tollgate.gateway.policy import PolicyHolder, load_policy
    from tollgate.gateway.replay import GITHUB_TRACE, run_trace

    off = copy.deepcopy(load_policy().data)
    off["taint"]["enabled"] = False

    PRS.clear()
    steps = await run_trace(PolicyHolder(off), GITHUB_TRACE)
    assert [s["verdict"] for s in steps] == ["allow", "allow", "allow"]
    assert len(PRS) == 1 and "SALARY_ALICE=182000" in PRS[0]["body"]  # roles alone: the leak happens
    assert "AKIA" not in PRS[0]["body"]  # the secret itself is redacted by content, salaries are not

    PRS.clear()
    steps = await run_trace(load_policy(), GITHUB_TRACE)
    assert [s["verdict"] for s in steps] == ["allow", "allow", "block"]
    msg = steps[2]["text"]
    assert "taint.flow" in msg and "github.issues.read #12" in msg and "github.repo.read" in msg
    assert PRS == []
