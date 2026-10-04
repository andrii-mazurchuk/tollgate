"""Session taint (TOLLGATE.md 4.4). A session = (role, key id): shared ids (in-process "local", the edge's "edge")
must not mix roles. STATE keys are "role:key_id" (key ids never hold ":"); calls without a role use the bare id.

ponytail: in-memory dict, lost on restart; move to the Hub store when the dashboard needs reset/history.
"""
STATE: dict[str, dict] = {}


def sid(key_id: str, role: str | None = None) -> str:
    return f"{role}:{key_id}" if role else key_id


def get(key_id: str, role: str | None = None) -> dict | None:
    """Read-only lookup (None = clean session)."""
    return STATE.get(sid(key_id, role))


def state(key_id: str, role: str | None = None) -> dict:
    return STATE.setdefault(sid(key_id, role), {"tainted": None, "holds_private": None})


def reset(key_id: str, role: str | None = None) -> None:
    """With a role: that session. Without: every role's session for this key id."""
    for k in [sid(key_id, role)] if role else [k for k in STATE if k == key_id or k.endswith(":" + key_id)]:
        STATE.pop(k, None)


def _labels(policy: dict, tool: str) -> list:
    return (policy.get("labels") or {}).get(tool) or []


def _cause(tool: str, args: dict) -> str:
    for k in ("number", "id"):
        if k in args:
            return f"{tool} #{args[k]}"
    where = ":".join(str(args[k]) for k in ("repo", "path", "sql") if k in args)
    return f"{tool} {where}".strip()


def record(policy: dict, key_id: str, tool: str, args: dict, labels: list | None = None, cause: str | None = None,
           role: str | None = None) -> None:
    """After a successful call. Taint never clears; the first cause is kept. `labels`/`cause` override (hook door)."""
    s = state(key_id, role)
    labels = _labels(policy, tool) if labels is None else labels
    if "untrusted_source" in labels and not s["tainted"]:
        s["tainted"] = cause or _cause(tool, args)
    if "private_data" in labels and not s["holds_private"]:
        s["holds_private"] = cause or _cause(tool, args)


def check(policy: dict, key_id: str, tool: str, labels: list | None = None, role: str | None = None) -> str | None:
    """Before a call. Returns the block message, or None to allow. block_flow.action (block|approve) is applied by the caller."""
    t = policy.get("taint") or {}
    if t.get("enabled") is False or "public_sink" not in (_labels(policy, tool) if labels is None else labels):
        return None
    s = get(key_id, role)
    if not s or not (s["tainted"] and s["holds_private"]):
        return None
    return f"blocked: session tainted by {s['tainted']}; private data from {s['holds_private']}"
