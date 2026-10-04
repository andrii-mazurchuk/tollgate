"""Per-call trace fields, the edge-local full-text store, and plain-English coverage of every rule ID."""
import json
import re
from pathlib import Path

import pytest

from tollgate import explain
from tollgate.contract import STAGES, AuditEvent, Reason
from tollgate.content.tier1 import RULES as T1
from tollgate.gateway import trace

pytestmark = pytest.mark.track_a
ROOT = Path(__file__).resolve().parents[1]


def _ev(verdict="allow", *rules, door="tool", key_id="k1"):
    return AuditEvent(ts="2026-10-03T00:00:00.000Z", role="role-2", key_id=key_id, door=door, verdict=verdict,
                      reasons=[Reason(rule=r, tier=0, detail=r) for r in rules])


def _chain(ev):
    return {s["name"]: s["outcome"] for s in trace.stages(ev)}


def test_stages_order_and_taint_block():
    st = trace.stages(_ev("block", "taint.flow"))
    assert [s["name"] for s in st] == list(STAGES)
    c = _chain(_ev("block", "taint.flow"))
    assert (c["key"], c["role"], c["arguments"], c["data_flow"], c["content"]) == ("ok", "ok", "ok", "fail", "skip")


def test_stages_redact_content_warn_and_role_fail():
    assert _chain(_ev("redact", "pii.email"))["content"] == "warn"
    c = _chain(_ev("block", "role.denied"))
    assert c["role"] == "fail" and c["arguments"] == "skip"
    assert _chain(_ev("block", "secret.aws_key"))["content"] == "fail"
    m = _chain(_ev("block", "budget.exceeded", door="model"))
    assert m["budget"] == "fail" and m["content"] == "skip"
    assert _chain(_ev("allow", door="model"))["budget"] == "ok"


def test_state_label():
    assert trace.label(None) == "clean"
    assert trace.label({"tainted": "x", "holds_private": None}) == "untrusted"
    assert trace.label({"tainted": "x", "holds_private": "y"}) == "untrusted+holds_private"


def _emitted_rules() -> set[str]:
    """Every rule ID string in the gateway/content source (explain.py itself excluded)."""
    pat = re.compile(r"[\"'](role|taint|content|budget|model|loop|approval|pin|feed|t2|upstream|auth|request|pii|"
                     r"secret|inj|sig)\.([a-z_]+)[\"']")
    found = set()
    for p in (ROOT / "tollgate").rglob("*.py"):
        if p.name != "explain.py":
            found |= {f"{a}.{b}" for a, b in pat.findall(p.read_text(encoding="utf-8"))}
    found |= {r[0] for r in T1}
    found |= {"approval.denied", "approval.timeout"}  # built as f"approval.{...}"
    return found - {"model.door", "secret.key"}  # secret.key: the install secret file name (gateway/keys.py)


def test_every_rule_has_a_plain_explanation():
    missing = [r for r in sorted(_emitted_rules()) if explain.rule(r) is explain.FALLBACK]
    assert not missing, missing
    assert explain.rule("sig.zz_demo")[0].startswith("The text matches a known attack")


def test_tool_names_and_sentence():
    assert explain.tool("github.pr.create") == "Open a pull request"
    ev = {"tool": "github.pr.create", "door": "tool", "verdict": "block",
          "reasons": [{"rule": "taint.flow", "detail": "x"}], "state_before": "untrusted+holds_private",
          "state_after": "untrusted+holds_private"}
    e = explain.event(ev)
    assert e["sentence"] == "Open a pull request: was blocked." and "outsiders" in e["why"]
    assert e["effect"] == "No change to the session."
    assert "Untrusted" in explain.effect("clean", "untrusted")


async def test_gateway_writes_trace_and_local_text(tmp_path, monkeypatch):
    monkeypatch.setenv("TOLLGATE_AUDIT", str(tmp_path / "events.jsonl"))
    monkeypatch.setenv("TOLLGATE_T2", "off")
    from mocks import tickets
    from tollgate.gateway import local_text
    from tollgate.gateway.policy import load_policy
    from tollgate.gateway.replay import run_trace

    tickets.reset()
    await run_trace(load_policy(), [("tickets.query", {"sql": "SELECT name, email FROM customers"})])
    ev = json.loads((tmp_path / "events.jsonl").read_text(encoding="utf-8").splitlines()[-1])
    assert ev["verdict"] == "redact" and ev["trace_id"] and ev["session_id"] == ev["key_id"]
    assert ev["state_before"] == "clean" and ev["state_after"] == "holds_private"
    assert [s["name"] for s in ev["stages"]] == list(STAGES)
    assert "jan@acme.pl" not in json.dumps(ev)  # full text never in the audit log
    txt = local_text.load()[ev["trace_id"]]
    assert "jan@acme.pl" in txt["result"]["original"] and "[EMAIL]" in txt["result"]["sent"]


def test_local_text_retention(tmp_path, monkeypatch):
    from tollgate.gateway import local_text
    monkeypatch.setenv("TOLLGATE_LOCAL_TEXT", str(tmp_path / "lt.jsonl"))
    monkeypatch.setattr(local_text, "KEEP", 5)
    for i in range(12):
        local_text.write(f"t{i}", {"args": {"original": str(i), "sent": str(i), "spans": []}})
    local_text.trim(local_text.path())
    assert list(local_text.load()) == [f"t{i}" for i in range(7, 12)]
