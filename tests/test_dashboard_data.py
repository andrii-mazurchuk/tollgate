"""Track B: dashboard data shaping (AC14), pure functions over audit event dicts."""
import csv
import io
import json
from datetime import datetime, timezone

import pytest

from dashboard import data

pytestmark = [pytest.mark.track_b]
NOW = datetime(2026, 10, 4, 10, 30, tzinfo=timezone.utc)


def ev(minute, verdict="allow", role="role-2", door="tool", key="k1", reasons=(), lat=None, **kw):
    return {"ts": f"2026-10-04T10:{minute:02d}:00.000Z", "role": role, "key_id": key, "door": door,
            "verdict": verdict, "reasons": [dict(rule=r, tier=t, detail=d, span=None) for r, t, d in reasons],
            "scan_point": "tool_args", "tool": "github.pr.create", "latency_ms": lat or {}, "tokens": 0, **kw}


EVENTS = [
    ev(1, lat={"role": 0.1, "taint": 0.01, "t1": 1.0}),
    ev(2, "redact", reasons=[("pii.iban", 1, "IBAN")], lat={"role": 0.3, "t1": 3.0, "t2": 40.0}),
    ev(3, "block", reasons=[("taint.flow", 0, "tainted by github.issues.read #12")], tainted=True, holds_private=True),
    ev(4, "block", role="role-1", key="k2", reasons=[("role.denied", 0, "no")]),
    ev(5, "block", reasons=[("taint.flow", 0, "later cause")], tainted=True, holds_private=True),
    ev(25, door="model", role="role-1", key="k2", tokens=600),
    ev(26, "block", door="model", role="role-1", key="k2", reasons=[("budget.exceeded", 0, "over")]),
]


def test_load_events_skips_torn_lines(tmp_path):
    p = tmp_path / "e.jsonl"
    p.write_text(json.dumps(EVENTS[0]) + "\n{not json\n" + json.dumps(EVENTS[1]) + "\n", encoding="utf-8")
    assert len(data.load_events(p)) == 2 and data.load_events(tmp_path / "missing.jsonl") == []


def test_counts_by_action_has_all_actions():
    assert data.counts_by_action(EVENTS) == {"allow": 2, "redact": 1, "approve": 0, "block": 4}
    assert data.counts_by(EVENTS, "door") == {"tool": 5, "model": 2}


def test_filters_and_window():
    assert len(data.filter_events(EVENTS, roles=["role-1"])) == 3
    assert len(data.filter_events(EVENTS, doors=["model"], verdicts=["block"])) == 1
    assert len(data.filter_events(EVENTS, minutes=15, now=NOW)) == 2


def test_series_buckets_by_minute():
    s = data.series_by_action(EVENTS[:3], bucket_s=600)
    assert len(s) == 1 and (s[0]["allow"], s[0]["redact"], s[0]["block"]) == (1, 1, 1)


def test_top_rules_with_tier():
    top = data.top_rules(EVENTS)
    assert top[0] == {"rule": "taint.flow", "tier": 0, "count": 2}
    assert {"rule": "pii.iban", "tier": 1, "count": 1} in top


def test_latency_percentiles_and_t2_share():
    lat = data.latency(EVENTS)
    assert lat["role"]["n"] == 2 and lat["role"]["p50"] == pytest.approx(0.2)
    assert lat["t2"] == {"p50": 40.0, "p95": 40.0, "n": 1}
    assert lat["t2_share"] == pytest.approx(1 / 7, abs=1e-4)
    assert data.latency([])["t2_share"] is None


def test_taint_table_uses_latest_cause_and_live_state():
    rows = data.taint_table(EVENTS)
    assert [r["key_id"] for r in rows] == ["k1"]
    assert rows[0]["cause"] == "later cause" and rows[0]["last_seen"].startswith("2026-10-04T10:05")
    live = {"k9": {"tainted": "github.issues.read #3", "holds_private": None}}
    rows = data.taint_table(EVENTS, live)
    k9 = next(r for r in rows if r["key_id"] == "k9")
    assert k9["tainted"] and not k9["holds_private"] and "issues.read #3" in k9["cause"]


def test_budget_from_events():
    b = data.budget_from_events(EVENTS, {"role-1": 1000, "role-2": None}, day="2026-10-04")
    assert b == {"role-1": {"used": 600, "limit": 1000}, "role-2": {"used": 0, "limit": None}}


def test_feed_newest_first_with_first_reason():
    f = data.feed(EVENTS, n=2)
    assert [r["verdict"] for r in f] == ["block", "allow"] and f[0]["rule"] == "budget.exceeded"


def test_exports():
    assert [json.loads(x) for x in data.to_jsonl(EVENTS).splitlines()] == EVENTS
    rows = list(csv.DictReader(io.StringIO(data.to_csv(EVENTS))))
    assert len(rows) == 7 and rows[2]["rule"] == "taint.flow" and json.loads(rows[1]["latency_ms"])["t2"] == 40.0


def test_approvals_view_and_offline():
    item = {"id": "ap_1a2b", "ts": "t", "role": "role-2", "key_id": "k1", "tool": "tickets.reply",
            "args_sha256": "ab", "reason": "taint.flow: x", "status": "pending", "decided_at": None}
    pending, recent = data.approvals_view({"pending": [item], "recent": [{**item, "status": "deny"}]})
    assert pending[0]["id"] == "ap_1a2b" and "args_sha256" not in pending[0] and recent[0]["status"] == "deny"
    assert data.approvals_view({"pending": [], "recent": []}) == ([], [])
    assert data.approvals_view(None) is None


def test_decision_message_and_pin_alerts():
    assert "token" in data.decision_message(401) and "already decided" in data.decision_message(404)
    alerts = data.pin_alerts({"pin_alerts": [{"tool": "github.pr.create", "old": "a" * 64, "new": "b" * 64, "ts": "t"}]})
    assert alerts == [f"github.pr.create: tool description changed: possible rug-pull ({'a' * 12} -> {'b' * 12} at t)"]
    assert data.pin_alerts(None) == [] and data.pin_alerts({"pin_alerts": []}) == []
