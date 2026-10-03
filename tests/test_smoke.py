"""Demo-path smoke checks. scripts/smoke.sh runs `pytest -m smoke`; it must pass before every merge to main.

Grow this as the demo path grows: one check per demo step, real components only.
"""
import pytest

from tollgate.content import scan
from tollgate.contract import Verdict

pytestmark = pytest.mark.smoke


def test_scan_honours_contract():
    v = scan("hello", "prompt", {})
    assert isinstance(v, Verdict)
    assert v.action in {"allow", "redact", "approve", "block"}


async def test_taint_blocks_github_replay(tmp_path, monkeypatch):
    """Demo step 2: the GitHub attack is allowed, allowed, then blocked by taint."""
    monkeypatch.setenv("TOLLGATE_AUDIT", str(tmp_path / "e.jsonl"))
    monkeypatch.setenv("TOLLGATE_T2", "off")  # no model in smoke; taint, not tier 2, makes this block
    from tollgate.gateway.policy import load_policy
    from tollgate.gateway.replay import run_trace

    assert [s["verdict"] for s in await run_trace(load_policy())] == ["allow", "allow", "block"]
