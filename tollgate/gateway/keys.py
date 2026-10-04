"""Role keys: tg_<role>_<keyid>_<hmac>. The key is the session (taint is keyed by it)."""
import hashlib
import hmac
import os
import secrets

import logging
from pathlib import Path

SECRET_FILE = Path(__file__).resolve().parents[2] / "audit/secret.key"  # audit/ is gitignored
_installed: dict[str, bytes] = {}


def install_secret() -> bytes:
    """Per-install random secret (never a constant from the public repo): created on first use at audit/secret.key
    (env TOLLGATE_SECRET_FILE), 0600. Used for role keys and the feed unless their env secret is set."""
    path = Path(os.environ.get("TOLLGATE_SECRET_FILE") or SECRET_FILE)
    if str(path) not in _installed:
        if not path.exists():
            path.parent.mkdir(parents=True, exist_ok=True)
            try:
                fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
                with os.fdopen(fd, "w") as f:
                    f.write(secrets.token_hex(32))
                logging.getLogger("tollgate").warning("generated a new install secret at %s", path)
            except FileExistsError:  # another process won the race: use its secret
                pass
        _installed[str(path)] = path.read_text().strip().encode()
        if len(_installed[str(path)]) < 32:
            raise RuntimeError(f"{path}: install secret too short; delete it to regenerate")
    return _installed[str(path)]


def _mac(role: str, key_id: str) -> str:
    secret = os.environ["TOLLGATE_KEY_SECRET"].encode() if os.environ.get("TOLLGATE_KEY_SECRET") else install_secret()
    return hmac.new(secret, f"{role}:{key_id}".encode(), hashlib.sha256).hexdigest()[:32]


def issue(role: str, key_id: str | None = None) -> str:
    key_id = key_id or "k" + secrets.token_hex(4)
    if any(c in role + key_id for c in "_:"):  # `_` splits the key, `:` splits the MAC payload
        raise ValueError("role and key_id must not contain '_' or ':'")
    return f"tg_{role}_{key_id}_{_mac(role, key_id)}"


def verify(key: str) -> tuple[str, str] | None:
    """Returns (role, key_id) or None. ponytail: no TTL yet; add expiry to the signed payload when needed."""
    parts = key.split("_")
    if len(parts) != 4 or parts[0] != "tg":
        return None
    _, role, key_id, mac = parts
    if ":" in role + key_id:  # MAC payload is `role:key_id`; (a, b:c) and (a:b, c) would share it
        return None
    return (role, key_id) if hmac.compare_digest(mac, _mac(role, key_id)) else None


def from_header(authorization: str | None) -> tuple[str, str] | None:
    if not authorization or not authorization.lower().startswith("bearer "):
        return None
    ident = verify(authorization[7:].strip())
    from tollgate.gateway import peers  # late: peers mints with issue()
    # every HTTP door (/mcp/{role}/ guard, RoleGate, model door) reads the key here: revoked peers stop at once
    return ident if ident and peers.is_key_allowed(*ident) else None
