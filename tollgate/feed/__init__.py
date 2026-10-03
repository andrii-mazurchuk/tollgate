"""P6 signature feed. Server: GET /bundle.json = {version, issued_at, signatures, sig}, sig = HMAC-SHA256 over the
canonical JSON of the other fields. Puller (gateway): verify, and if newer, atomically rewrite signatures.yaml, which
tollgate.content.signatures hot reloads by mtime."""
import hashlib
import hmac
import json
import os
import re
from datetime import datetime, timezone
from pathlib import Path

import httpx2
import yaml
from starlette.applications import Starlette
from starlette.responses import JSONResponse
from starlette.routing import Route

DEV_SECRET = "tollgate-dev-feed-secret"
SRC = "bundle_src.yaml"
_STAMP = re.compile(r"#\s*feed-version:\s*(\d+)")


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")


def _sig(body: dict) -> str:
    key = (os.environ.get("TOLLGATE_FEED_SECRET") or DEV_SECRET).encode()
    canon = json.dumps(body, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()
    return hmac.new(key, canon, hashlib.sha256).hexdigest()


def bundle(feed_dir) -> dict:
    src = yaml.safe_load((Path(feed_dir) / SRC).read_text(encoding="utf-8")) or {}
    body = {"version": int(src.get("version", 1)), "issued_at": src.get("issued_at") or _now(),
            "signatures": src.get("signatures") or []}
    return {**body, "sig": _sig(body)}


def publish(feed_dir, spec: str) -> int:
    """spec: 'id=..,pattern=..,action=block,tags=A;B' (a pattern may contain commas). Returns the new version."""
    entry = dict(kv.split("=", 1) for kv in re.split(r",(?=(?:id|pattern|action|tags)=)", spec))
    if not entry.get("id") or not entry.get("pattern"):
        raise ValueError("need at least id=... and pattern=...")
    re.compile(entry["pattern"])  # refuse a broken regex at the source
    entry.setdefault("action", "block")
    entry["tags"] = [t for t in entry.get("tags", "").split(";") if t]
    path = Path(feed_dir) / SRC
    src = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    sigs = [s for s in src.get("signatures") or [] if s.get("id") != entry["id"]] + [entry]
    src.update(version=int(src.get("version", 0)) + 1, issued_at=_now(), signatures=sigs)
    path.write_text(yaml.safe_dump(src, sort_keys=False, allow_unicode=True), encoding="utf-8", newline="\n")
    return src["version"]


def build_feed_app(feed_dir) -> Starlette:
    async def get_bundle(_):  # re-read per request: `feed publish` from another process shows up immediately
        return JSONResponse(bundle(feed_dir))
    return Starlette(routes=[Route("/bundle.json", get_bundle)])


class Puller:
    def __init__(self, url: str | None, transport=None):
        self.transport = transport
        self.state = {"url": url, "version": None, "last_pull": None, "last_error": None}

    async def pull(self, target) -> bool:
        """One cycle. True if signatures.yaml was rewritten. Errors land in state.last_error, never raise."""
        target = Path(target)
        self.state["last_pull"] = _now()
        try:
            async with httpx2.AsyncClient(transport=self.transport, timeout=10) as c:
                r = await c.get(self.state["url"])
                r.raise_for_status()
                b = r.json()
            body = {k: b[k] for k in ("version", "issued_at", "signatures")}
            if not hmac.compare_digest(str(b.get("sig", "")), _sig(body)):
                raise ValueError("bad bundle signature (HMAC mismatch); rejected")
            if not isinstance(body["signatures"], list) or not isinstance(body["version"], int):
                raise ValueError("malformed bundle")
        except Exception as e:
            self.state["last_error"] = f"{type(e).__name__}: {e}"
            return False
        self.state["last_error"] = None
        if self.state["version"] is None and target.exists():  # restart: trust the stamp in the file
            m = _STAMP.search(target.read_text(encoding="utf-8").partition("\n")[0])
            self.state["version"] = int(m.group(1)) if m else None
        if self.state["version"] is not None and body["version"] <= self.state["version"]:
            return False
        tmp = target.with_name(target.name + ".tmp")
        tmp.write_text(f"# feed-version: {body['version']}  issued_at: {body['issued_at']}  (written by the feed "
                       f"puller; edit the feed, not this file)\n"
                       + yaml.safe_dump(body["signatures"], sort_keys=False, allow_unicode=True), encoding="utf-8", newline="\n")
        os.replace(tmp, target)
        self.state["version"] = body["version"]
        return True
