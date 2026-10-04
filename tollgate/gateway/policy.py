"""Loads policy.yaml and hot reloads it (AC7). The gateway reads `holder.data` on every request; a changed file
is validated and swapped in, an invalid one is rejected (old policy kept, error in `status()`). Every load and reload
attempt is kept in `history` and appended to policy_history.jsonl next to the audit log (survives restarts)."""
import hashlib
import json
import logging
import os
from datetime import datetime, timezone
from pathlib import Path

import yaml

DEFAULT_PATH = Path(__file__).resolve().parents[2] / "policy.yaml"
log = logging.getLogger("tollgate.policy")


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")


class PolicyHolder:
    def __init__(self, data: dict, path: str | Path | None = None, raw: bytes | None = None):
        self.path = Path(path) if path else None
        self._data = data
        self.version = hashlib.sha256(raw or json.dumps(data, sort_keys=True, default=str).encode()).hexdigest()[:8]
        self.loaded_at, self.last_error = _now(), None
        self._stamp = self._stat()
        try:
            lines = history_path().read_text(encoding="utf-8").splitlines()
            self.history = [json.loads(x) for x in lines if x.strip()]
        except (OSError, ValueError):
            self.history = []
        if self.path:
            self._record(True, data.get("mode") if isinstance(data, dict) else None)

    def _record(self, ok: bool, profile, version: str | None = None, error: str | None = None, note: str | None = None):
        e = {"version": version or self.version, "at": _now(), "profile": profile, "ok": ok, "error": error}
        if note:
            e["note"] = note  # e.g. "Edited in console"; older entries have no note
        last = self.history[-1] if self.history else {}
        if ok and last.get("ok") and last.get("version") == e["version"]:
            return  # a restart (or a CLI one-shot) on the same file is not a new version
        self.history.append(e)
        try:
            hp = history_path()
            hp.parent.mkdir(parents=True, exist_ok=True)
            with hp.open("a", encoding="utf-8") as f:
                f.write(json.dumps(e) + "\n")
        except OSError as x:
            log.error("policy history not written: %s", x)

    def _stat(self):
        try:
            st = os.stat(self.path) if self.path else None
            return st and (st.st_mtime_ns, st.st_size)
        except OSError:
            return None

    @property
    def data(self) -> dict:
        # ponytail: one stat() per access; cheap locally, throttle if the file lives on a slow mount
        if self.path and (stamp := self._stat()) != self._stamp:
            self._stamp = stamp
            self.reload()
        return self._data

    def reload(self, note: str | None = None) -> bool:
        self._stamp, raw, data = self._stat(), None, None
        try:
            raw = self.path.read_bytes()
            data = yaml.safe_load(raw)
            validate(data)
        except Exception as e:  # any bad file: keep the old policy
            self.last_error = {"message": f"{type(e).__name__}: {e}", "at": _now()}
            log.error("policy reload rejected, keeping %s: %s", self.version, self.last_error["message"])
            self._record(False, data.get("mode") if isinstance(data, dict) else None,
                         raw and hashlib.sha256(raw).hexdigest()[:8], self.last_error["message"])
            return False
        self._data, self.last_error, self.loaded_at = data, None, _now()
        self.version = hashlib.sha256(raw).hexdigest()[:8]
        log.warning("policy reloaded: %s", self.version)
        self._record(True, data.get("mode"), note=note)
        return True

    def status(self) -> dict:
        self.data  # pick up a pending edit first
        return {"version": self.version, "loaded_at": self.loaded_at, "last_error": self.last_error,
                "path": str(self.path) if self.path else None}


def history_path() -> Path:
    from tollgate.gateway import audit
    return Path(os.environ.get("TOLLGATE_AUDIT") or audit.DEFAULT_PATH).parent / "policy_history.jsonl"


LABELS = {"untrusted_source", "private_data", "public_sink"}


SERVER_KEYS = {"mock": set(), "url": {"headers", "transport"}, "command": {"args", "env", "cwd"}}


def validate_server(name: str, s) -> None:
    """servers.<name>: exactly one of mock: module | url: http(s)://... | command: exe (see docs/connectivity.md)."""
    kind = [k for k in SERVER_KEYS if k in (s if isinstance(s, dict) else {})]
    if len(kind) != 1:
        raise ValueError(f"servers.{name}: need exactly one of mock: module | url: https://... | command: exe")
    k = kind[0]
    if extra := set(s) - {k} - SERVER_KEYS[k]:
        raise ValueError(f"servers.{name}: unknown keys {sorted(extra)} for a {k}: server")
    is_str_map = lambda v: isinstance(v, dict) and all(isinstance(x, str) for x in v.values())  # noqa: E731
    if not isinstance(s[k], str) or not s[k] or (k == "url" and not s[k].startswith(("http://", "https://", "${"))):
        raise ValueError(f"servers.{name}.{k}: need a non-empty string" + (" starting http(s)://" if k == "url" else ""))
    if not is_str_map(s.get("headers", {})) or not is_str_map(s.get("env", {})):
        raise ValueError(f"servers.{name}: headers/env need a mapping of strings")
    if s.get("transport", "http") not in ("http", "sse"):
        raise ValueError(f"servers.{name}.transport: need http|sse")
    if not isinstance(s.get("args", []), list) or not all(isinstance(a, str) for a in s.get("args", [])):
        raise ValueError(f"servers.{name}.args: need a list of strings")
    if not isinstance(s.get("cwd", ""), str):
        raise ValueError(f"servers.{name}.cwd: need a string")


def validate(p) -> dict:
    """Checks A's sections only; `content` is passed through untouched (Track B)."""
    if not isinstance(p, dict):
        raise ValueError("policy must be a mapping")
    servers, roles = p.get("servers") or {}, p.get("roles")
    if not isinstance(servers, dict) or not isinstance(roles, dict):
        raise ValueError("servers and roles must be mappings")
    for name, s in servers.items():
        validate_server(name, s)
    for role, r in roles.items():
        if not isinstance(r, dict) or not isinstance(r.get("servers") or {}, dict):
            raise ValueError(f"roles.{role}: must be a mapping with servers: {{...}}")
        for srv, spec in (r.get("servers") or {}).items():
            if srv not in servers:
                raise ValueError(f"roles.{role}.servers.{srv}: unknown server")
            if not isinstance(spec, dict) or (
                    spec.get("access") not in ("read", "rw") and not isinstance(spec.get("tools"), list)):
                raise ValueError(f"roles.{role}.servers.{srv}: need access: read|rw or tools: [...]")
            if "tools" in spec and not (isinstance(spec["tools"], list) and all(isinstance(t, str) for t in spec["tools"])):
                raise ValueError(f"roles.{role}.servers.{srv}.tools: need a list of tool names")  # a string would substring-match
        if not isinstance(r.get("content") or {}, dict):
            raise ValueError(f"roles.{role}.content: need a mapping of content keys")
        for tool, c in (r.get("constrain") or {}).items():
            if not isinstance(c, dict) or tool.split(".")[0] not in servers \
                    or not all(isinstance(v, str) for v in c.values()):
                raise ValueError(f"roles.{role}.constrain.{tool}: bad constraint (want {{arg: glob|select_only}})")
        if not all(isinstance(m, str) for m in r.get("models") or []) or not isinstance(r.get("models") or [], list):
            raise ValueError(f"roles.{role}.models: need a list of model names")
        if not isinstance(r.get("approval") or [], list) or not all(isinstance(t, str) for t in r.get("approval") or []):
            raise ValueError(f"roles.{role}.approval: need a list of tool names")
        tpd = (r.get("budget") or {}).get("tokens_per_day")
        if tpd is not None and (not isinstance(tpd, int) or isinstance(tpd, bool) or tpd < 0):
            raise ValueError(f"roles.{role}.budget.tokens_per_day: need a non-negative integer")
    labels = p.get("labels") or {}
    if not isinstance(labels, dict) or not all(
            isinstance(v, list) and set(v) <= LABELS for v in labels.values()):  # a typo would silently drop a sink
        raise ValueError(f"labels: need {{tool: [...]}} with labels from {sorted(LABELS)}")
    t = p.get("taint") or {}
    if not isinstance(t, dict) or (t.get("block_flow") or {}).get("action", "block") not in ("block", "approve"):
        raise ValueError("taint.block_flow.action: need block|approve")
    if "enabled" in t and not isinstance(t["enabled"], bool):
        raise ValueError("taint.enabled: need true|false")
    ts = (p.get("approval") or {}).get("timeout_s", 30)
    if not isinstance(ts, (int, float)) or isinstance(ts, bool) or ts <= 0:
        raise ValueError("approval.timeout_s: need a number > 0")
    mic = (p.get("loops") or {}).get("max_identical_calls", 5)
    if not isinstance(mic, int) or isinstance(mic, bool) or mic < 1:
        raise ValueError("loops.max_identical_calls: need an integer >= 1")
    f = p.get("feed")
    if f is not None and (not isinstance(f, dict) or not isinstance(f.get("url"), str)
                          or not isinstance(f.get("interval_s", 10), (int, float)) or f.get("interval_s", 10) <= 0):
        raise ValueError("feed: need {url: http://..., interval_s: number > 0}")
    return p


def load_policy(path: str | Path = DEFAULT_PATH) -> PolicyHolder:
    """Strict at startup (no old policy to fall back to): raises on an invalid file."""
    raw = Path(path).read_bytes()
    return PolicyHolder(validate(yaml.safe_load(raw)), path, raw)
