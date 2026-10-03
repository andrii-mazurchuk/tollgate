"""Loads policy.yaml and hot reloads it (AC7). The gateway reads `holder.data` on every request; a changed file
is validated and swapped in, an invalid one is rejected (old policy kept, error in `status()`)."""
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

    def reload(self) -> bool:
        try:
            raw = self.path.read_bytes()
            data = validate(yaml.safe_load(raw))
        except Exception as e:  # any bad file: keep the old policy
            self.last_error = {"message": f"{type(e).__name__}: {e}", "at": _now()}
            log.error("policy reload rejected, keeping %s: %s", self.version, self.last_error["message"])
            return False
        self._data, self.last_error, self.loaded_at = data, None, _now()
        self.version = hashlib.sha256(raw).hexdigest()[:8]
        log.warning("policy reloaded: %s", self.version)
        return True

    def status(self) -> dict:
        self.data  # pick up a pending edit first
        return {"version": self.version, "loaded_at": self.loaded_at, "last_error": self.last_error,
                "path": str(self.path) if self.path else None}


def validate(p) -> dict:
    """Checks A's sections only; `content` is passed through untouched (Track B)."""
    if not isinstance(p, dict):
        raise ValueError("policy must be a mapping")
    servers, roles = p.get("servers") or {}, p.get("roles")
    if not isinstance(servers, dict) or not isinstance(roles, dict):
        raise ValueError("servers and roles must be mappings")
    for role, r in roles.items():
        if not isinstance(r, dict) or not isinstance(r.get("servers") or {}, dict):
            raise ValueError(f"roles.{role}: must be a mapping with servers: {{...}}")
        for srv, spec in (r.get("servers") or {}).items():
            if srv not in servers:
                raise ValueError(f"roles.{role}.servers.{srv}: unknown server")
            if not isinstance(spec, dict) or (
                    spec.get("access") not in ("read", "rw") and not isinstance(spec.get("tools"), list)):
                raise ValueError(f"roles.{role}.servers.{srv}: need access: read|rw or tools: [...]")
        for tool, c in (r.get("constrain") or {}).items():
            if not isinstance(c, dict) or tool.split(".")[0] not in servers \
                    or not all(isinstance(v, str) for v in c.values()):
                raise ValueError(f"roles.{role}.constrain.{tool}: bad constraint (want {{arg: glob|select_only}})")
        if not all(isinstance(m, str) for m in r.get("models") or []) or not isinstance(r.get("models") or [], list):
            raise ValueError(f"roles.{role}.models: need a list of model names")
        tpd = (r.get("budget") or {}).get("tokens_per_day")
        if tpd is not None and (not isinstance(tpd, int) or isinstance(tpd, bool) or tpd < 0):
            raise ValueError(f"roles.{role}.budget.tokens_per_day: need a non-negative integer")
    t = p.get("taint") or {}
    if not isinstance(t, dict) or (t.get("block_flow") or {}).get("action", "block") not in ("block", "approve"):
        raise ValueError("taint.block_flow.action: need block|approve")
    if "enabled" in t and not isinstance(t["enabled"], bool):
        raise ValueError("taint.enabled: need true|false")
    mic = (p.get("loops") or {}).get("max_identical_calls", 5)
    if not isinstance(mic, int) or isinstance(mic, bool) or mic < 1:
        raise ValueError("loops.max_identical_calls: need an integer >= 1")
    return p


def load_policy(path: str | Path = DEFAULT_PATH) -> PolicyHolder:
    """Strict at startup (no old policy to fall back to): raises on an invalid file."""
    raw = Path(path).read_bytes()
    return PolicyHolder(validate(yaml.safe_load(raw)), path, raw)
