"""Signature feed: signatures.yaml as tier 1 rules, reloaded when the file's mtime changes."""
import logging
import os
import re
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[2]  # policy paths are relative to the repo root, not the CWD

log = logging.getLogger(__name__)
_ACTIONS = ("allow", "redact", "approve", "block")
_missing: set[str] = set()
_cache: dict[str, tuple[int, list, list[str]]] = {}  # path -> (mtime_ns, rules, errors)


def _load(path: str) -> tuple[list, list[str]]:
    rules, errors = [], []
    with open(path, encoding="utf-8") as f:
        entries = yaml.safe_load(f) or []
    if not isinstance(entries, list):
        return [], [f"{path}: top level must be a list"]
    for i, e in enumerate(entries):
        try:
            sid, action = str(e["id"]), e.get("action", "block")
            if action not in _ACTIONS:
                raise ValueError(f"bad action {action!r}")
            rx = re.compile(e["pattern"], re.I)
            tags = ",".join(map(str, e.get("tags") or []))
            rules.append((f"sig.{sid}", rx, action, f"signature {sid}" + (f" [{tags}]" if tags else "")))
        except Exception as exc:  # skip and record, never crash the scan
            errors.append(f"entry {i}: {type(exc).__name__}: {exc}")
    for err in errors:
        log.warning("signatures %s: %s", path, err)
    return rules, errors


def rules(path: str | None) -> list:
    """(rule_id, regex, action, detail) for the feed at path. Cheap: one stat per call."""
    if not path:
        return []
    path = str(ROOT / path)  # absolute paths pass through unchanged
    try:
        mtime = os.stat(path).st_mtime_ns
    except OSError:
        if path not in _missing:  # warn once per path, rules() runs on every scan
            _missing.add(path)
            log.warning("signatures file %s not found: tier 1 feed has 0 signatures", path)
        return []
    hit = _cache.get(path)
    if hit is None or hit[0] != mtime:
        try:
            hit = (mtime, *_load(path))
        except Exception as exc:  # unreadable/invalid YAML: keep the last good feed if any
            log.warning("signatures %s: %s", path, exc)
            hit = (mtime, hit[1] if hit else [], [f"{type(exc).__name__}: {exc}"])
        _cache[path] = hit
    return hit[1]


def errors(path: str) -> list[str]:
    rules(path)
    return _cache.get(str(ROOT / path), (0, [], []))[2]
