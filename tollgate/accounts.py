"""Console accounts (audit/accounts.json, env TOLLGATE_ACCOUNTS): users, one-time invites, browser sessions.

Two roles: admin (changes things) and viewer (reads everything). Passwords are scrypt; invite tokens and session ids
are stored only as sha256. Every admin change is appended to admin_log.jsonl next to the store.

ponytail: one JSON file under a process lock (like gateway/peers.py); a DB when users or processes grow.
"""
import hashlib
import hmac
import json
import os
import re
import secrets
import threading
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path

DEFAULT_PATH = Path(__file__).resolve().parents[1] / "audit" / "accounts.json"
ROLES = ("admin", "viewer")
MIN_PW = 12
INVITE_TTL = timedelta(hours=24)
SESSION_TTL = timedelta(hours=12)
COOKIE = "tg_session"
FAIL_MAX, FAIL_WINDOW_S = 5, 300
N, R, P = 2 ** 14, 8, 1  # scrypt: ~16 MB, ~50 ms
EMAIL = re.compile(r"^[^@\s]{1,64}@[^@\s]{1,190}$")
_LOCK = threading.Lock()
_CACHE: dict = {}
_FAILS: dict[tuple, list[float]] = {}  # ponytail: in-memory, per process; resets on restart


def path() -> Path:
    return Path(os.environ.get("TOLLGATE_ACCOUNTS") or DEFAULT_PATH)


def log_path() -> Path:
    return path().with_name("admin_log.jsonl")


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _iso(t: datetime) -> str:
    return t.isoformat(timespec="seconds").replace("+00:00", "Z")


def _sha(s: str) -> str:
    return hashlib.sha256(s.encode()).hexdigest()


def load() -> dict:
    """The store; callers must not mutate it (use _update)."""
    p = path()
    try:
        st = p.stat()
        sig = (str(p), st.st_mtime_ns, st.st_size)
        if _CACHE.get("sig") != sig:
            _CACHE.update(sig=sig, data=json.loads(p.read_text(encoding="utf-8")))
        return _CACHE["data"]
    except (OSError, ValueError):
        return {"users": {}, "invites": {}, "sessions": {}}


def _update(fn):
    with _LOCK:
        db = json.loads(json.dumps(load()))
        for k in ("users", "invites", "sessions"):
            db.setdefault(k, {})
        now = _iso(_now())
        db["sessions"] = {k: v for k, v in db["sessions"].items() if v["expires_at"] > now}  # prune expired
        out = fn(db)
        p = path()
        p.parent.mkdir(parents=True, exist_ok=True)
        tmp = p.with_suffix(".tmp")
        tmp.write_text(json.dumps(db, indent=1, ensure_ascii=False), encoding="utf-8")
        os.replace(tmp, p)
        st = p.stat()
        _CACHE.update(sig=(str(p), st.st_mtime_ns, st.st_size), data=db)
        return out


def any_users() -> bool:
    return bool(load().get("users"))


# --- passwords ---
def hash_pw(pw: str) -> str:
    salt = secrets.token_bytes(16)
    return f"scrypt${salt.hex()}${hashlib.scrypt(pw.encode(), salt=salt, n=N, r=R, p=P, dklen=32).hex()}"


_DUMMY = hash_pw(secrets.token_hex(8))  # verified against when the email is unknown: same time either way


def check_pw(pw: str, stored: str) -> bool:
    try:
        _, salt, h = stored.split("$")
        got = hashlib.scrypt(pw.encode(), salt=bytes.fromhex(salt), n=N, r=R, p=P, dklen=32).hex()
    except (ValueError, AttributeError):
        return False
    return hmac.compare_digest(got, h)


def norm_email(e) -> str:
    e = (e or "").strip().lower() if isinstance(e, str) else ""
    if not EMAIL.match(e):
        raise ValueError("Enter a valid email address.")
    return e


def _pw_ok(pw) -> str:
    if not isinstance(pw, str) or len(pw) < MIN_PW:
        raise ValueError(f"The password needs at least {MIN_PW} characters.")
    if len(pw) > 1024:
        raise ValueError("The password is too long.")
    return pw


def _name(name, email: str) -> str:
    name = (name or "").strip() if isinstance(name, str) else ""
    return name[:80] or email.split("@")[0]


# --- users ---
def create_user(email, password, role: str = "admin", name=None, only_if_empty: bool = False) -> dict:
    """Raises ValueError on bad input, an existing email, or (only_if_empty) when any account exists."""
    email, password = norm_email(email), _pw_ok(password)
    if role not in ROLES:
        raise ValueError(f"role must be one of {ROLES}")
    pw = hash_pw(password)

    def f(db):
        if only_if_empty and db["users"]:
            raise ValueError("An owner account already exists. Sign in instead.")
        if email in db["users"]:
            raise ValueError("An account with this email already exists.")
        db["users"][email] = {"name": _name(name, email), "role": role, "pw": pw, "created_at": _iso(_now()),
                              "disabled": False, "last_login": None}
        return public(email, db["users"][email])
    return _update(f)


def public(email: str, u: dict) -> dict:
    return {"email": email, "name": u["name"], "role": u["role"], "created_at": u["created_at"],
            "last_login": u.get("last_login"), "disabled": bool(u.get("disabled"))}


def listing() -> list[dict]:
    return sorted((public(e, u) for e, u in load()["users"].items()), key=lambda u: u["created_at"])


def _active_admins(db) -> set:
    return {e for e, u in db["users"].items() if u["role"] == "admin" and not u.get("disabled")}


def set_role(email: str, role: str, actor: str) -> dict:
    if role not in ROLES:
        raise ValueError(f"role must be one of {ROLES}")

    def f(db):
        u = db["users"].get(email)
        if not u:
            raise KeyError(email)
        if role != "admin" and _active_admins(db) == {email}:
            raise ValueError("This is the last admin. Make someone else an admin first.")
        u["role"] = role
        return public(email, u)
    out = _update(f)
    log(actor, f"Changed {email}'s role to {role}")
    return out


def set_disabled(email: str, disabled: bool, actor: str) -> dict:
    def f(db):
        u = db["users"].get(email)
        if not u:
            raise KeyError(email)
        if disabled and email == actor:
            raise ValueError("You cannot disable your own account.")
        if disabled and _active_admins(db) == {email}:
            raise ValueError("This is the last admin. Make someone else an admin first.")
        u["disabled"] = bool(disabled)
        if disabled:  # sign them out everywhere now
            db["sessions"] = {k: v for k, v in db["sessions"].items() if v["email"] != email}
        return public(email, u)
    out = _update(f)
    log(actor, f"{'Disabled' if disabled else 'Enabled'} {email}")
    return out


# --- invites (capability links: 192-bit token, 24 h, one use, only the sha256 stored) ---
def invite(email, role: str, actor: str) -> dict:
    email = norm_email(email)
    if role not in ROLES:
        raise ValueError(f"role must be one of {ROLES}")
    token, exp = secrets.token_urlsafe(24), _iso(_now() + INVITE_TTL)

    def f(db):
        if email in db["users"]:
            raise ValueError("An account with this email already exists.")
        db["invites"][_sha(token)] = {"email": email, "role": role, "expires_at": exp, "used_at": None, "by": actor}
    _update(f)
    log(actor, f"Invited {email} as {role}")
    return {"token": token, "email": email, "role": role, "expires_at": exp}


def accept(token, name, password) -> dict:
    """Invite -> account. Raises ValueError on an unknown, used or expired invite or a weak password."""
    password = _pw_ok(password)
    if not isinstance(token, str) or not token:
        raise ValueError("This invite link is not valid.")
    pw = hash_pw(password)

    def f(db):
        inv = db["invites"].get(_sha(token))
        if not inv or inv["used_at"] or inv["expires_at"] < _iso(_now()):
            raise ValueError("This invite link is not valid, already used, or expired. Ask an admin for a new one.")
        if inv["email"] in db["users"]:
            raise ValueError("An account with this email already exists.")
        inv["used_at"] = _iso(_now())
        db["users"][inv["email"]] = {"name": _name(name, inv["email"]), "role": inv["role"], "pw": pw,
                                     "created_at": _iso(_now()), "disabled": False, "last_login": None}
        return public(inv["email"], db["users"][inv["email"]])
    out = _update(f)
    log(out["email"], f"Accepted an invite as {out['role']}")
    return out


# --- login + sessions ---
class RateLimited(Exception):
    pass


def login(email, password, ip: str, old_sid: str | None = None) -> tuple[str, dict]:
    """(session id, user). Raises ValueError('Wrong email or password') or RateLimited."""
    e = (email or "").strip().lower() if isinstance(email, str) else ""
    k, t = (ip, e), time.monotonic()
    fails = _FAILS[k] = [x for x in _FAILS.get(k, []) if t - x < FAIL_WINDOW_S]
    if len(fails) >= FAIL_MAX:
        raise RateLimited()
    u = load()["users"].get(e)
    ok = check_pw(password if isinstance(password, str) else "", u["pw"] if u else _DUMMY)
    if not (u and ok and not u.get("disabled")):
        fails.append(t)
        raise ValueError("Wrong email or password")
    _FAILS.pop(k, None)
    return new_session(e, old_sid)


def new_session(email: str, old_sid: str | None = None) -> tuple[str, dict]:
    sid = secrets.token_urlsafe(32)

    def f(db):
        if old_sid:
            db["sessions"].pop(_sha(old_sid), None)  # rotate: the pre-login id never stays valid
        db["sessions"][_sha(sid)] = {"email": email, "expires_at": _iso(_now() + SESSION_TTL),
                                     "csrf": secrets.token_urlsafe(32)}
        db["users"][email]["last_login"] = _iso(_now())
        return public(email, db["users"][email])
    return sid, _update(f)


def session(sid: str | None) -> dict | None:
    """{email, name, role, csrf} for a live session of an enabled user, else None."""
    if not sid:
        return None
    db = load()
    s = db["sessions"].get(_sha(sid))
    if not s or s["expires_at"] <= _iso(_now()):
        return None
    u = db["users"].get(s["email"])
    if not u or u.get("disabled"):
        return None
    return {"email": s["email"], "name": u["name"], "role": u["role"], "csrf": s["csrf"]}


def logout(sid: str | None) -> None:
    if sid:
        _update(lambda db: db["sessions"].pop(_sha(sid), None))


# --- admin log ---
def log(who: str, what: str) -> None:
    p = log_path()
    p.parent.mkdir(parents=True, exist_ok=True)
    with p.open("a", encoding="utf-8") as f:
        f.write(json.dumps({"ts": _iso(_now()), "who": who, "what": what}, ensure_ascii=False) + "\n")


def recent_log(n: int = 50) -> list[dict]:
    try:
        lines = log_path().read_text(encoding="utf-8").splitlines()
    except OSError:
        return []
    out = []
    for x in lines[-n:][::-1]:
        try:
            out.append(json.loads(x))
        except ValueError:
            pass
    return out
