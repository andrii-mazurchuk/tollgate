"""Approval flow (TOLLGATE.md 4.3): an `approve` verdict parks the call until an admin decides or the timeout hits.

ponytail: in-memory, one per app; pending approvals die with the process (the waiting call fails closed).
"""
import asyncio
import hmac
import os
import secrets
from datetime import datetime, timezone

KEEP = 200  # decided items kept for GET /admin/approvals


def admin_ok(authorization: str | None) -> bool:
    """Separate from role keys, so an agent can't approve its own call. No TOLLGATE_ADMIN_TOKEN set: the token path is
    off (there is no default token)."""
    token = os.environ.get("TOLLGATE_ADMIN_TOKEN")
    if not token:
        return False
    given = (authorization or "")[7:].strip() if (authorization or "").lower().startswith("bearer ") else ""
    return bool(given) and hmac.compare_digest(given, token)


LOCAL_HOSTS = ("127.0.0.1", "localhost", "::1")


def host_ok(request) -> bool:
    """The Host header names this server (anti DNS rebinding): loopback names, or TOLLGATE_ALLOWED_HOSTS (comma list)."""
    h = (request.headers.get("host") or "").strip().lower()
    h = h[1:].split("]")[0] if h.startswith("[") else h.rsplit(":", 1)[0] if h.count(":") == 1 else h
    extra = {x.strip().lower() for x in (os.environ.get("TOLLGATE_ALLOWED_HOSTS") or "").split(",") if x.strip()}
    return h in LOCAL_HOSTS or h in extra


def loopback(request) -> bool:
    return bool(request.client and request.client.host in LOCAL_HOSTS) and host_ok(request)


def admin_request(request) -> bool:
    """Admin reads (/admin/*, /healthz details): the admin token, or loopback until the first console account exists
    (then loopback no longer bypasses sign-in). ponytail: behind a reverse proxy every client looks loopback."""
    from tollgate import accounts
    return admin_ok(request.headers.get("authorization")) or (not accounts.any_users() and loopback(request))


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")


class Approvals:
    def __init__(self):
        self.items: dict[str, dict] = {}
        self._decided: dict[str, asyncio.Event] = {}
        self._new = asyncio.Event()

    def create(self, role: str, key_id: str, tool: str, args_sha256: str, reason: str) -> dict:
        item = {"id": "ap_" + secrets.token_hex(4), "ts": _now(), "role": role, "key_id": key_id, "tool": tool,
                "args_sha256": args_sha256, "reason": reason, "status": "pending", "decided_at": None}
        self.items[item["id"]] = item
        self._decided[item["id"]] = asyncio.Event()
        self._new.set()
        done = [k for k, v in self.items.items() if v["status"] != "pending"]
        for k in done[:-KEEP]:
            del self.items[k]
        return item

    async def wait(self, item: dict, timeout_s: float) -> str:
        """Returns approve | deny | timeout."""
        try:
            await asyncio.wait_for(self._decided[item["id"]].wait(), timeout_s)
        except TimeoutError:
            self._close(item, "timeout")
        self._decided.pop(item["id"], None)
        return item["status"]

    def decide(self, id: str, decision: str) -> dict | None:
        item = self.items.get(id)
        if not item or item["status"] != "pending" or decision not in ("approve", "deny"):
            return None
        self._close(item, decision)
        self._decided[id].set()
        return item

    def _close(self, item: dict, status: str) -> None:
        item["status"], item["decided_at"] = status, _now()

    def listing(self) -> dict:
        items = list(self.items.values())
        return {"pending": [i for i in items if i["status"] == "pending"],
                "recent": [i for i in reversed(items) if i["status"] != "pending"][:50]}

    async def next_pending(self) -> dict:
        """Test/CLI helper: waits until a pending item exists, returns the oldest."""
        while not (p := self.listing()["pending"]):
            self._new.clear()
            await self._new.wait()
        return p[0]
