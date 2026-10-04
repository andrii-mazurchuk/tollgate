"""Audit JSONL writer (docs/process/API_CONTRACT.md 2). One AuditEvent per call decision; never raw content."""
import asyncio
import dataclasses
import json
import os
from pathlib import Path
from tollgate import paths

from tollgate.contract import AuditEvent

DEFAULT_PATH = paths.AUDIT / "events.jsonl"
LISTENERS: set[asyncio.Queue] = set()  # edge SSE: each gets the trace_id of every written event


def write(event: AuditEvent) -> None:
    from tollgate.gateway import trace  # late: trace imports nothing from here, but keep audit import-light

    event.session_id = event.session_id or event.key_id
    event.trace_id = event.trace_id or trace.new_id()
    if not event.stages:
        event.stages = trace.stages(event)
    path = Path(os.environ.get("TOLLGATE_AUDIT") or DEFAULT_PATH)
    path.parent.mkdir(parents=True, exist_ok=True)
    # ponytail: append per event, no lock; fine for one process
    with path.open("a", encoding="utf-8") as f:
        f.write(json.dumps(dataclasses.asdict(event), ensure_ascii=False) + "\n")
    for q in list(LISTENERS):
        q.put_nowait(event.trace_id)
