"""Role keys: tg_<role>_<keyid>_<hmac>. The key is the session (taint is keyed by it)."""
import hashlib
import hmac
import os
import secrets

DEV_SECRET = "tollgate-dev-secret-change-me"


def _mac(role: str, key_id: str) -> str:
    secret = os.environ.get("TOLLGATE_KEY_SECRET", DEV_SECRET).encode()
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
    return verify(authorization[7:].strip())
