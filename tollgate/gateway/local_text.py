"""Edge-only full text store: audit/local_text.jsonl keyed by trace_id (original and masked args/results/prompts).

Never part of the audit log or anything sent to the server. Gitignored (audit/). Keeps the last KEEP calls.
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


def write(trace_id: str, texts: dict) -> None:
    """texts: {"args"|"result"|"prompt"|"response": {"original": str, "sent": str, "spans": [[s, e], ...]}}."""
    global _writes
    if not texts:
        return
    p = path()
    p.parent.mkdir(parents=True, exist_ok=True)
    with p.open("a", encoding="utf-8") as f:
        f.write(json.dumps({"trace_id": trace_id, **texts}, ensure_ascii=False) + "\n")
    _writes += 1
    if _writes % 100 == 0:  # ponytail: trim every 100 writes, so the file peaks at KEEP+100 lines
        trim(p)


def trim(p: Path) -> None:
    lines = p.read_text(encoding="utf-8").splitlines(keepends=True)
    if len(lines) > KEEP:
        p.write_text("".join(lines[-KEEP:]), encoding="utf-8")


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
