"""Audit JSONL writer (API_CONTRACT.md 2). One AuditEvent per call decision; never raw content."""
import dataclasses
import json
import os
from pathlib import Path

from tollgate.contract import AuditEvent

DEFAULT_PATH = Path(__file__).resolve().parents[2] / "audit" / "events.jsonl"


def write(event: AuditEvent) -> None:
    path = Path(os.environ.get("TOLLGATE_AUDIT") or DEFAULT_PATH)
    path.parent.mkdir(parents=True, exist_ok=True)
    # ponytail: append per event, no lock; fine for one process
    with path.open("a", encoding="utf-8") as f:
        f.write(json.dumps(dataclasses.asdict(event), ensure_ascii=False) + "\n")
