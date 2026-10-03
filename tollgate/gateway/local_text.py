"""Edge-only full text store: audit/local_text.jsonl keyed by trace_id (original and masked args/results/prompts).

Never part of the audit log or anything sent to the server. Gitignored (audit/). Keeps the last `retention` calls.
Local settings (audit/edge_settings.json) may only be stricter than the company policy's `edge:` ceiling.
"""
import json
import os
from pathlib import Path

from tollgate.gateway import audit

KEEP = 2000
_writes = 0


def path() -> Path:
    return Path(os.environ.get("TOLLGATE_LOCAL_TEXT") or Path(os.environ.get("TOLLGATE_AUDIT") or audit.DEFAULT_PATH)
                .with_name("local_text.jsonl"))


def settings_path() -> Path:
    return Path(os.environ.get("TOLLGATE_EDGE_SETTINGS") or path().with_name("edge_settings.json"))


THEMES = ("system", "light", "dark")


def ceiling(policy: dict) -> dict:
    """The loosest the company policy allows: `edge: {keep_text: bool, retention: int}`, default keep and KEEP."""
    e = policy.get("edge") or {}
    return {"keep_text": e.get("keep_text", True) is True, "retention": int(e.get("retention", KEEP))}


def check_settings(new: dict, ceil: dict) -> dict:
    """Validates a settings change; raises ValueError if malformed or looser than the policy ceiling."""
    if not isinstance(new, dict) or set(new) - {"keep_text", "retention", "theme"}:
        raise ValueError("only keep_text, retention and theme can be set")
    if "keep_text" in new and not isinstance(new["keep_text"], bool):
        raise ValueError("keep_text: need true or false")
    r = new.get("retention", 1)
    if not isinstance(r, int) or isinstance(r, bool) or r < 1:
        raise ValueError("retention: need a whole number of calls, at least 1")
    if new.get("theme", "system") not in THEMES:
        raise ValueError(f"theme: need one of {', '.join(THEMES)}")
    if new.get("keep_text") and not ceil["keep_text"]:
        raise ValueError("the company policy does not allow keeping full text on this laptop")
    if r > ceil["retention"]:
        raise ValueError(f"the company policy allows at most {ceil['retention']} calls of retention")
    return new


def settings() -> dict:
    out = {"keep_text": True, "retention": KEEP, "theme": "system"}
    try:
        saved = json.loads(settings_path().read_text(encoding="utf-8"))
        out.update({k: v for k, v in saved.items() if k in out})
    except (OSError, ValueError, AttributeError):
        pass
    return out


def save_settings(new: dict) -> dict:
    s = {**settings(), **new}
    p = settings_path()
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(json.dumps(s, indent=2), encoding="utf-8")
    return s


def write(trace_id: str, texts: dict) -> None:
    """texts: {"args"|"result"|"prompt"|"response": {"original": str, "sent": str, "spans": [[s, e], ...]}}."""
    global _writes
    # ponytail: one small file read per call; cache on mtime if this ever shows in the latency budget
    st = settings()
    if not texts or not st["keep_text"]:
        return
    p = path()
    p.parent.mkdir(parents=True, exist_ok=True)
    with p.open("a", encoding="utf-8") as f:
        f.write(json.dumps({"trace_id": trace_id, **texts}, ensure_ascii=False) + "\n")
    _writes += 1
    if _writes % min(100, st["retention"]) == 0:  # ponytail: trim in batches, so the file peaks at ~2x retention
        trim(p)


def trim(p: Path) -> None:
    keep = settings()["retention"]
    lines = p.read_text(encoding="utf-8").splitlines(keepends=True)
    if len(lines) > keep:
        p.write_text("".join(lines[-keep:]), encoding="utf-8")


def load() -> dict[str, dict]:
    try:
        lines = path().read_text(encoding="utf-8").splitlines()
    except OSError:
        return {}
    out = {}
    for line in lines:
        try:
            row = json.loads(line)
            out[row.pop("trace_id")] = row
        except (ValueError, KeyError, AttributeError):
            continue
    return out
