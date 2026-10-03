import pytest

from tollgate.gateway import taint

pytestmark = [pytest.mark.track_a]

POLICY = {
    "labels": {"gh.issue": ["untrusted_source"], "gh.read": ["private_data"], "gh.pr": ["public_sink"]},
    "taint": {"block_flow": {"action": "block"}},
}


def test_blocks_only_when_tainted_and_holding_private():
    taint.reset("k")
    assert taint.check(POLICY, "k", "gh.pr") is None
    taint.record(POLICY, "k", "gh.issue", {"number": 12})
    assert taint.check(POLICY, "k", "gh.pr") is None  # tainted alone: benign flow ok
    taint.record(POLICY, "k", "gh.read", {"path": ".env"})
    msg = taint.check(POLICY, "k", "gh.pr")
    assert msg.startswith("blocked: session tainted by gh.issue #12; private data from gh.read")
    assert taint.check(POLICY, "other", "gh.pr") is None  # per key
    assert taint.check({**POLICY, "taint": {"enabled": False}}, "k", "gh.pr") is None
    taint.reset("k")
    assert taint.check(POLICY, "k", "gh.pr") is None


def test_check_returns_message_for_approve_too():
    """The caller turns the message into a block or an approval request (tests/acceptance/test_helpers.py)."""
    taint.reset("k")
    taint.record(POLICY, "k", "gh.issue", {"number": 1})
    taint.record(POLICY, "k", "gh.read", {})
    msg = taint.check({**POLICY, "taint": {"block_flow": {"action": "approve"}}}, "k", "gh.pr")
    assert msg.startswith("blocked: session tainted by")
    taint.reset("k")
