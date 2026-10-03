"""Session taint (TOLLGATE.md 4.4). A session = one role key; in-process calls use key_id "local".

ponytail: in-memory dict, lost on restart; move to the Hub store when the dashboard needs reset/history.
"""
STATE: dict[str, dict] = {}


def state(key_id: str) -> dict:
    return STATE.setdefault(key_id, {"tainted": None, "holds_private": None})


def reset(key_id: str) -> None:
    STATE.pop(key_id, None)


def _labels(policy: dict, tool: str) -> list:
    return (policy.get("labels") or {}).get(tool) or []


def _cause(tool: str, args: dict) -> str:
    for k in ("number", "id"):
        if k in args:
            return f"{tool} #{args[k]}"
    where = ":".join(str(args[k]) for k in ("repo", "path", "sql") if k in args)
    return f"{tool} {where}".strip()


def record(policy: dict, key_id: str, tool: str, args: dict) -> None:
    """After a successful call. Taint never clears; the first cause is kept."""
    s, labels = state(key_id), _labels(policy, tool)
    if "untrusted_source" in labels and not s["tainted"]:
        s["tainted"] = _cause(tool, args)
    if "private_data" in labels and not s["holds_private"]:
        s["holds_private"] = _cause(tool, args)


def check(policy: dict, key_id: str, tool: str) -> str | None:
    """Before a call. Returns the block message, or None to allow."""
    t = policy.get("taint") or {}
    if t.get("enabled") is False or "public_sink" not in _labels(policy, tool):
        return None
    s = STATE.get(key_id)
    if not s or not (s["tainted"] and s["holds_private"]):
        return None
    msg = f"blocked: session tainted by {s['tainted']}; private data from {s['holds_private']}"
    if (t.get("block_flow") or {}).get("action", "block") == "approve":
        msg += " (approve not built yet; treated as block)"
    return msg
