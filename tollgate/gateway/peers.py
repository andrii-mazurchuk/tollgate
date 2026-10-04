"""Peer registry (audit/peers.json, env TOLLGATE_PEERS): laptops enroll once with a one-time token, the admin sets the
roles each may run, and every agent launch mints a key `tg_<role>_<peer>-<n>_<mac>`. from_header checks it here.

ponytail: one JSON file under a process lock, re-read when its mtime changes; a DB when peers or processes grow."""
import hashlib
import json
import os
import secrets
import threading
from datetime import datetime, timedelta, timezone
from pathlib import Path

from tollgate.gateway import keys

DEFAULT_PATH = Path(__file__).resolve().parents[2] / "audit" / "peers.json"
TOKEN_TTL = timedelta(hours=24)
_LOCK = threading.Lock()
_CACHE: dict = {}


def path() -> Path:
    return Path(os.environ.get("TOLLGATE_PEERS") or DEFAULT_PATH)


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _iso(t: datetime) -> str:
    return t.isoformat(timespec="seconds").replace("+00:00", "Z")


def load() -> dict:
    """The registry; callers must not mutate it (use _update)."""
    p = path()
    try:
        st = p.stat()
        sig = (str(p), st.st_mtime_ns, st.st_size)
        if _CACHE.get("sig") != sig:
            _CACHE.update(sig=sig, data=json.loads(p.read_text(encoding="utf-8")))
        return _CACHE["data"]
    except (OSError, ValueError):
        return {"peers": {}, "tokens": {}}


def _update(fn):
    """Read-modify-write under the lock; fn(reg) mutates reg and returns the result."""
    with _LOCK:
        reg = json.loads(json.dumps(load()))
        reg.setdefault("peers", {}), reg.setdefault("tokens", {})
        out = fn(reg)
        p = path()
        p.parent.mkdir(parents=True, exist_ok=True)
        tmp = p.with_suffix(".tmp")
        tmp.write_text(json.dumps(reg, indent=1, ensure_ascii=False), encoding="utf-8")
        os.replace(tmp, p)
        return out


def _sha(token: str) -> str:
    return hashlib.sha256(token.encode()).hexdigest()


def enroll_token() -> dict:
    """{token, expires_at}. Only the token's sha256 is stored."""
    token, exp = "tge_" + secrets.token_urlsafe(18), _iso(_now() + TOKEN_TTL)

    def f(reg):
        reg["tokens"][_sha(token)] = {"expires_at": exp, "used_at": None, "peer": None}
    _update(f)
    return {"token": token, "expires_at": exp}


def enroll(token: str, owner: str, device: str) -> str:
    """Peer id (`p` + 4 hex). Raises ValueError on an unknown, used or expired token."""
    def f(reg):
        t = reg["tokens"].get(_sha(token))
        if not t or t["used_at"] or t["expires_at"] < _iso(_now()):
            raise ValueError("enroll token unknown, already used or expired")
        pid = "p" + secrets.token_hex(2)
        while pid in reg["peers"]:
            pid = "p" + secrets.token_hex(2)
        reg["peers"][pid] = {"owner": owner, "device": device, "roles": [], "enrolled_at": _iso(_now()),
                             "revoked_at": None, "minted": 0}
        t.update(used_at=_iso(_now()), peer=pid)
        return pid
    return _update(f)


def _peer(reg: dict, pid: str) -> dict:
    if pid not in reg["peers"]:
        raise KeyError(pid)
    return reg["peers"][pid]


def set_roles(pid: str, roles: list[str]) -> dict:
    """Removing a role kills the keys minted for it so far (`cut`), so re-adding it doesn't revive them."""
    def f(reg):
        p = _peer(reg, pid)
        for r in set(p["roles"]) - set(roles):
            p.setdefault("cut", {})[r] = p["minted"]
        p["roles"] = sorted(set(roles))
        return p
    return _update(f)


def revoke(pid: str) -> dict:
    def f(reg):
        p = _peer(reg, pid)
        p["revoked_at"] = p["revoked_at"] or _iso(_now())
        return p
    return _update(f)


def mint(pid: str, role: str, known_roles) -> str:
    """A fresh key for one agent launch. Refused (ValueError) for a revoked peer or a role it may not run."""
    if role not in known_roles:
        raise ValueError(f"unknown role {role}")

    def f(reg):
        p = _peer(reg, pid)
        if p["revoked_at"]:
            raise ValueError(f"peer {pid} is revoked")
        if role not in p["roles"]:
            raise ValueError(f"peer {pid} may not run {role}")
        p["minted"] += 1
        return keys.issue(role, f"{pid}-{p['minted']}")
    return _update(f)


def peer_of(key_id: str) -> str | None:
    """`p3f9a-4` -> `p3f9a`; legacy key ids without `-` have no peer (Unenrolled)."""
    return key_id.split("-")[0] if "-" in key_id else None


def is_key_allowed(role: str, key_id: str) -> bool:
    pid = peer_of(key_id)
    if pid is None:
        return True
    p = load()["peers"].get(pid)
    n = key_id.split("-", 1)[1]
    return bool(p and not p["revoked_at"] and role in p["roles"] and n.isdigit()
                and int(n) > (p.get("cut") or {}).get(role, 0))


def label(pid: str | None, reg: dict | None = None) -> str:
    p = (reg or load())["peers"].get(pid) if pid else None
    return f"{p['device']} · {p['owner']}" if p else ("Unenrolled" if pid is None else pid)
