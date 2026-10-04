"""Per-call trace (API_CONTRACT.md 2, optional fields): trace ids, session state labels, and the check chain
derived from an event's reasons, so both doors share one definition."""
import secrets

from tollgate.contract import STAGES, AuditEvent


def new_id() -> str:
    return "t_" + secrets.token_hex(6)


def label(st: dict | None) -> str:
    """Taint state -> clean | untrusted | holds_private | untrusted+holds_private."""
    st = st or {}
    return "+".join(n for n, f in (("untrusted", "tainted"), ("holds_private", "holds_private")) if st.get(f)) or "clean"


def stage_of(rule: str, detail: str = "") -> str:
    """Which check in the chain a reason belongs to."""
    if rule == "auth.invalid" or (rule == "role.denied" and detail.startswith("key not bound")):
        return "key"
    if rule in ("role.denied", "role.builtin_denied", "pin.changed", "model.denied"):
        return "role"
    if rule in ("role.constraint", "loop.cutoff") or rule.startswith("request."):
        return "arguments"
    if rule.startswith("taint."):
        return "data_flow"
    if rule.startswith("budget."):
        return "budget"
    if rule.startswith("approval.") or rule == "role.approval":
        return "approval"
    return "content"  # pii.* secret.* inj.* sig.* t2.* content.* upstream.*


FLAG = ("inj.", "sig.", "t2.injection", "t2.suspect")  # content findings that mark text without changing the verdict


def stages(ev: AuditEvent) -> list[dict]:
    """The check chain for one decision: [{name, outcome: ok|warn|fail|skip, detail, ms}] in STAGES order."""
    by: dict[str, list] = {s: [] for s in STAGES}
    for r in ev.reasons:
        by[stage_of(r.rule, r.detail)].append(r)
    lat = ev.latency_ms or {}
    ms = {"role": lat.get("role"), "data_flow": lat.get("taint"),
          "content": round(lat.get("t1", 0) + lat.get("t2", 0), 3) if ("t1" in lat or "t2" in lat) else None}
    out, stopped = [], False
    for s in STAGES:
        rs = by[s]
        detail = "; ".join(r.detail or r.rule for r in rs)
        if stopped and s != "approval":
            outcome = "skip"
        elif s == "key" and ev.key_id == "local" and not rs:
            outcome = "skip"  # in-process call: no key to check
        elif s == "budget" and ev.door in ("tool", "hook"):
            outcome = "skip"  # tool calls are not metered
        elif s == "approval":
            rules = {r.rule for r in rs}
            outcome = ("fail" if rules & {"approval.denied", "approval.timeout"} else "ok" if "approval.approved" in rules
                       else "warn" if rules else "skip")
        elif s == "content":  # blocked with no other check failing (budget runs before content at the model door)
            later = bool(by["budget"]) or bool({r.rule for r in by["approval"]} & {"approval.denied", "approval.timeout"})
            outcome = ("skip" if by["budget"] else "fail" if ev.verdict == "block" and not later
                       else "warn" if ev.verdict == "redact" or any(r.rule.startswith(FLAG) for r in rs) else "ok")
        elif s == "data_flow" and rs:
            outcome = "fail" if ev.verdict == "block" else "warn"
        else:
            outcome = "fail" if rs else "ok"
        stopped = stopped or outcome == "fail"
        out.append({"name": s, "outcome": outcome, "detail": detail, "ms": ms.get(s)})
    return out
