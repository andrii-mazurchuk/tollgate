import pytest

pytestmark = [pytest.mark.track_a]


def test_ac15_hub_and_tier1_latency(tmp_path, monkeypatch):
    """AC15: Hub checks (role + taint) p95 < 5 ms and tier 1 p95 < 5 ms, measured through the gateway."""
    monkeypatch.setenv("TOLLGATE_AUDIT", str(tmp_path / "events.jsonl"))
    from tollgate.gateway.perf import measure

    res = measure(n=50)
    s = res["stages_ms"]
    assert s["role"]["n"] > 0 and s["taint"]["n"] > 0 and s["t1"]["n"] > 0
    assert res["wall_ms"]["denied"]["n"] == 50 and res["overhead_ms"]["p50"] is not None
    assert s["hub"]["p95"] < 5.0
    assert s["t1"]["p95"] < 5.0
