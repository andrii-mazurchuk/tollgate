import copy

import pytest

pytestmark = [pytest.mark.track_a]


async def test_ac05_supabase_replay(tmp_path, monkeypatch):
    """AC5 part 2: Supabase trace (ticket -> SELECT customers -> reply) leaks with taint off, is blocked with taint on."""
    monkeypatch.setenv("TOLLGATE_AUDIT", str(tmp_path / "events.jsonl"))
    from mocks.tickets import replies, reset
    from tollgate.gateway.policy import PolicyHolder, load_policy
    from tollgate.gateway.replay import SUPABASE_TRACE, run_trace

    on = load_policy()
    assert on.data["labels"]["tickets.read"] == ["untrusted_source"]
    off = copy.deepcopy(on.data)
    off["taint"]["enabled"] = False

    reset()
    steps = await run_trace(PolicyHolder(off), SUPABASE_TRACE)
    assert [s["verdict"] for s in steps] == ["allow", "allow", "allow"]
    leaked = replies()[3]
    assert "Jan Kowalski" in leaked and "Anna Nowak" in leaked  # roles alone: customer rows land in the ticket
    assert "PL61" not in leaked  # the IBAN itself is redacted by content; names are not PII rules

    reset()
    steps = await run_trace(on, SUPABASE_TRACE)
    assert [s["verdict"] for s in steps] == ["allow", "allow", "block"]
    msg = steps[2]["text"]
    assert "taint.flow" in msg and "tickets.read #3" in msg and "tickets.query" in msg
    assert 3 not in replies()
