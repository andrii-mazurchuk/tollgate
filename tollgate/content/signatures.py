"""Signature feed: signatures.yaml as tier 1 rules, reloaded when the file's mtime changes."""
import logging
import os
import re
import time
from pathlib import Path
from tollgate import paths

import yaml

ROOT = paths.HOME  # policy paths are relative to the Tollgate home (the repo root in a checkout), not the CWD

log = logging.getLogger(__name__)
_ACTIONS = ("allow", "redact", "approve", "block")
MAX_PATTERN = 500
# a quantified group whose body is itself quantified: (a+)+, (\w*)*, (x+y?){2,}; catastrophic backtracking
_NESTED = re.compile(r"\((?:[^()\\]|\\.)*[+*}](?:[^()\\]|\\.)*\)\s*(?:[+*]|\{\d*,)")
# alternation under a repeat ((a|aa)+) and the same token quantified twice in a row (\w*\w*): overlapping choices
_ALT_REPEAT = re.compile(r"\((?:[^()\\]|\\.)*\|(?:[^()\\]|\\.)*\)\s*(?:[+*]|\{\d*,)")
_ADJACENT = re.compile(r"(\\.|\[(?:\\.|[^\]])*\]|\.|\w)[+*]\??\1[+*]")
PROBE_BUDGET_S = 0.05  # one probe search slower than this = super-linear backtracking


def _slow(rx: re.Pattern, pat: str) -> bool:
    """Times the compiled pattern on adversarial non-matching runs (each char repeated, then NUL), growing the
    length in small steps so an exponential pattern is caught before one probe takes long."""
    chars = dict.fromkeys(re.findall(r"[a-z0-9]", re.sub(r"\\.", "", pat.lower()))[:6] + ["a", " ", "0", "_", ".", "-"])
    for n in [*range(8, 64, 4), 64, 128, 256, 512, 1024, 2000]:
        for c in chars:
            t0 = time.perf_counter()
            rx.search(c * n + "\x00")
            if time.perf_counter() - t0 > PROBE_BUDGET_S:
                return True
    return False


def check_pattern(pat: str) -> re.Pattern:
    """Compiled (re.I) pattern, or ValueError when it is too long, ReDoS-shaped, or measured slow. Used at feed
    publish, feed pull and signatures.yaml load. ponytail: probes, not proof; a `regex` timeout would be exact."""
    if len(pat) > MAX_PATTERN or _NESTED.search(pat) or _ALT_REPEAT.search(pat) or _ADJACENT.search(pat):
        raise ValueError("pattern rejected: too long, nested/adjacent quantifier or alternation under repeat (ReDoS risk)")
    rx = re.compile(pat, re.I)
    if _slow(rx, pat):
        raise ValueError(f"pattern rejected: a probe search took over {PROBE_BUDGET_S * 1000:.0f} ms (ReDoS risk)")
    return rx


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
            pat = str(e["pattern"])
            rx = check_pattern(pat)  # ReDoS guard: the feed is external input
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
