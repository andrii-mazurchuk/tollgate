"""Peer registry (enroll once, roles, mint, revoke) and the server console API (/console/api/*)."""
import contextlib
import json
import os
from datetime import datetime, timedelta, timezone
from pathlib import Path

import httpx2
import pytest

from tests.conftest import ADMIN

WRITE = {**ADMIN, "Content-Type": "application/json"}  # writes need the admin token (or a session) and JSON

from tollgate.gateway import keys, peers

pytestmark = pytest.mark.track_a
ROLES = ("role-1", "role-2")


@pytest.fixture(autouse=True)
def _peers_to_tmp(tmp_path, monkeypatch):
    monkeypatch.setenv("TOLLGATE_PEERS", str(tmp_path / "peers.json"))


def _peer(*roles, device="dev-laptop"):
    pid = peers.enroll(peers.enroll_token()["token"], "Ada", device)
    peers.set_roles(pid, list(roles))
    return pid


def test_token_is_one_time_hashed_and_expires(tmp_path):
    t = peers.enroll_token()
    assert t["token"] not in (tmp_path / "peers.json").read_text()
    pid = peers.enroll(t["token"], "Ada", "ada-x1")
    assert len(pid) == 5 and pid[0] == "p" and int(pid[1:], 16) >= 0
    with pytest.raises(ValueError):
        peers.enroll(t["token"], "Eve", "eve-pc")
    old = peers.enroll_token()
    reg = json.loads((tmp_path / "peers.json").read_text())
    for v in reg["tokens"].values():
        if v["used_at"] is None:
            v["expires_at"] = "2000-01-01T00:00:00Z"
    (tmp_path / "peers.json").write_text(json.dumps(reg))
    with pytest.raises(ValueError):
        peers.enroll(old["token"], "Eve", "eve-pc")


def test_mint_refusals_and_revocation():
    pid = _peer("role-2")
    k = peers.mint(pid, "role-2", ROLES)
    assert keys.verify(k) == ("role-2", f"{pid}-1") and keys.from_header(f"Bearer {k}")
    for role in ("role-1", "role-9"):
        with pytest.raises(ValueError):
            peers.mint(pid, role, ROLES)
    with pytest.raises(KeyError):
        peers.mint("pffff", "role-2", ROLES)
    peers.set_roles(pid, ["role-1"])
    assert keys.from_header(f"Bearer {k}") is None  # role removed: its keys die
    peers.set_roles(pid, ["role-1", "role-2"])
    assert keys.from_header(f"Bearer {k}") is None  # and stay dead when the role comes back
    k2 = peers.mint(pid, "role-2", ROLES)
    assert keys.from_header(f"Bearer {k2}")
    peers.revoke(pid)
    assert keys.from_header(f"Bearer {k2}") is None
    with pytest.raises(ValueError):
        peers.mint(pid, "role-2", ROLES)
    assert keys.from_header(f"Bearer {keys.issue('role-2')}") is None  # unenrolled keys: refused by default
    assert keys.from_header(f"Bearer {keys.issue('role-2')}", allow_unenrolled=True)  # policy allow_unenrolled_keys
    assert keys.from_header(f"Bearer {keys.issue('role-2', 'pabcd-1')}") is None  # unknown peer


@contextlib.asynccontextmanager
async def _app(monkeypatch):
    monkeypatch.setenv("TOLLGATE_UPSTREAM", "scripted")
    from tollgate.gateway import build_app
    from tollgate.gateway.policy import load_policy

    app = build_app(load_policy())
    async with app.router.lifespan_context(app):
        async with httpx2.AsyncClient(transport=httpx2.ASGITransport(app=app), base_url="http://127.0.0.1:8080", headers=WRITE) as c:
            yield c, app


LIST = {"jsonrpc": "2.0", "id": 1, "method": "tools/list"}


async def test_revoked_peer_gets_401_over_http(monkeypatch):
    async with _app(monkeypatch) as (c, _):
        pid = _peer("role-2")
        k = peers.mint(pid, "role-2", ROLES)
        h = {"Authorization": f"Bearer {k}", "Accept": "application/json, text/event-stream"}
        assert (await c.post("/mcp/role-2/", headers=h, json=LIST)).status_code != 401
        chat = {"model": "qwen3:4b", "messages": [{"role": "user", "content": "Hi"}]}
        assert (await c.post("/v1/chat/completions", headers=h, json=chat)).status_code == 200
        assert (await c.post(f"/console/api/peers/{pid}/revoke")).json()["revoked"]
        assert (await c.post("/mcp/role-2/", headers=h, json=LIST)).status_code == 401
        assert (await c.post("/v1/chat/completions", headers=h, json=chat)).status_code == 401


async def test_console_api_shapes(monkeypatch):
    from tollgate import scenario
    async with _app(monkeypatch) as (c, app):
        tok = (await c.post("/console/api/enroll-token")).json()
        assert tok["command"].startswith(f"tollgate enroll {tok['token']} --owner") and tok["expires_at"].endswith("Z")
        pid = peers.enroll(tok["token"], "Ada", "ada-x1")
        assert (await c.post(f"/console/api/peers/{pid}/roles", json={"roles": ["role-9"]})).status_code == 400
        p = (await c.post(f"/console/api/peers/{pid}/roles", json={"roles": ["role-2"]})).json()
        assert p["roles"] == ["role-2"] and p["label"] == "ada-x1 · Ada" and not p["revoked"]

        class Fleet(scenario.Runner):  # the Acme attack with a minted key, plus one legacy-key session
            def key(self, step):
                if step["session"] not in self.keys:
                    self.keys[step["session"]] = peers.mint(pid, "role-2", ROLES)
                return self.keys[step["session"]]
        r = Fleet(app)
        r.reset()
        for s in ("3.1", "3.2", "3.3"):
            assert (await r.run(s))["pass"]
        assert (await scenario.Runner(app).run("2.1"))["pass"]

        st = (await c.get("/console/api/status")).json()
        assert st["health"]["message"] == "1 attack stopped" and st["admin"] == "token"
        assert set(st) == {"health", "admin", "policy", "feed", "app_version"}

        ov = (await c.get("/console/api/overview", params={"range": "15m"})).json()
        k = ov["kpis"]
        assert k["checked"]["value"] == 4 and k["blocked"]["value"] == 1 and k["attacks"]["value"] == 1
        assert k["peers_online"]["value"] == 1
        assert ov["by_role"] == [{"role": "role-2", "agent": "Support assistant", "count": 1}]
        assert ov["by_reason"] == [{"label": "Data-flow rule", "count": 1}] and ov["series"] and ov["bucket_s"]
        a = ov["attacks"][0]
        assert a["peer"] == pid and a["peer_label"] == "ada-x1 · Ada" and a["kind"] == "blocked"

        ps = (await c.get("/console/api/peers")).json()
        assert {r["role"] for r in ps["roles"]} == set(ROLES)
        r2 = next(r for r in ps["roles"] if r["role"] == "role-2")
        assert r2["peers"] == 1 and r2["blocked"] == 1 and {"name", "allowed", "hidden"} <= set(r2["servers"][0])
        rows = {r["id"]: r for r in ps["peers"]}
        assert rows[pid]["online"] and rows[pid]["actions"] == 3 and rows[pid]["sessions"] == 1
        assert rows["unenrolled"]["label"] == "Unenrolled" and rows["unenrolled"]["actions"] == 1

        d = (await c.get(f"/console/api/peers/{pid}")).json()
        assert d["keys"][0]["key_id"] == f"{pid}-1" and d["keys"][0]["n"] == 3 and len(d["sessions"]) == 1
        assert (await c.get("/console/api/peers/pzzzz")).status_code == 404

        role = (await c.get("/console/api/roles/role-2")).json()
        assert role["agent"] == "Support assistant" and [p["id"] for p in role["peers"]] == [pid]
        assert (await c.get("/console/api/roles/nope")).status_code == 404

        ss = (await c.get("/console/api/sessions", params={"peer": pid})).json()["sessions"]
        assert len(ss) == 1 and ss[0]["peer_label"] == "ada-x1 · Ada"
        assert len((await c.get("/console/api/sessions", params={"role": "role-1"})).json()["sessions"]) == 0
        one = (await c.get(f"/console/api/sessions/{ss[0]['id']}")).json()
        assert [e["verdict"] for e in one["timeline"]] == ["allow", "redact", "block"]
        assert all("text" not in e and len(e["content_sha256"]) == 64 for e in one["timeline"])
        assert "AKIA" not in json.dumps(one)

        assert (await c.get("/console/")).status_code == 200


async def test_console_needs_loopback_or_admin_token(monkeypatch):
    async with _app(monkeypatch) as (_, app):
        async with httpx2.AsyncClient(transport=httpx2.ASGITransport(app=app, client=("10.1.2.3", 5000)),
                                      base_url="http://127.0.0.1") as remote:
            assert (await remote.get("/console/api/peers")).status_code == 401
            assert (await remote.post("/console/api/enroll-token", json={})).status_code == 401
            from tests.conftest import ADMIN_TOKEN as ADMIN_DEV_TOKEN
            r = await remote.get("/console/api/status", headers={"Authorization": f"Bearer {ADMIN_DEV_TOKEN}"})
            assert r.status_code == 200 and r.json()["admin"] == "token"


def test_peer_online_window():
    from tollgate import console
    now = datetime(2026, 10, 4, 10, 0, tzinfo=timezone.utc)

    def ev(min_ago, key_id):
        return {"ts": (now - timedelta(minutes=min_ago)).isoformat().replace("+00:00", "Z"), "key_id": key_id,
                "session_id": key_id, "role": "role-2", "verdict": "allow"}
    reg = {"peers": {"pa000": {"owner": "A", "device": "a", "roles": ["role-2"], "revoked_at": None},
                     "pb000": {"owner": "B", "device": "b", "roles": ["role-2"], "revoked_at": None}}, "tokens": {}}
    rows = {r["id"]: r for r in console.peer_rows([ev(1, "pa000-1"), ev(9, "pb000-2")], reg, now)}
    assert rows["pa000"]["online"] and not rows["pb000"]["online"] and "unenrolled" not in rows


@contextlib.asynccontextmanager
async def _policy_app(monkeypatch, tmp_path):
    """Gateway on a tmp copy of policy.yaml: a profile switch must never overwrite the repo's file."""
    monkeypatch.setenv("TOLLGATE_UPSTREAM", "scripted")
    from tollgate.gateway import build_app
    from tollgate.gateway.policy import DEFAULT_PATH, load_policy

    path = tmp_path / "policy.yaml"
    path.write_bytes(DEFAULT_PATH.read_bytes())
    holder = load_policy(path)
    app = build_app(holder)
    async with app.router.lifespan_context(app):
        async with httpx2.AsyncClient(transport=httpx2.ASGITransport(app=app), base_url="http://127.0.0.1:8080", headers=WRITE) as c:
            yield c, app, holder


async def test_policy_view_shape_and_matrix(monkeypatch, tmp_path):
    async with _policy_app(monkeypatch, tmp_path) as (c, _, holder):
        p = (await c.get("/console/api/policy")).json()
        assert set(p) == {"status", "matrix", "rules", "history", "profiles"}
        st = p["status"]
        assert st["version"] == holder.version and st["profile"] == "balanced" and st["modified"] is False
        assert st["last_error"] is None and st["path"].endswith("policy.yaml") and st["loaded_at"]
        assert p["matrix"]["roles"] == [{"role": "role-1", "agent": "Intern bot"},
                                        {"role": "role-2", "agent": "Support assistant"}]
        cell = {t["name"]: t for s in p["matrix"]["servers"] for t in s["tools"]}
        assert {s["name"] for s in p["matrix"]["servers"]} == {"github", "tickets", "files"}
        assert cell["github.pr.create"]["cells"]["role-1"]["access"] == "hidden"
        assert cell["github.pr.create"]["cells"]["role-2"]["access"] == "write"
        assert cell["github.pr.create"]["labels"] == ["public destination"]
        assert cell["github.issues.read"]["cells"]["role-1"] == {"access": "read", "limits": []}
        assert cell["files.fs.delete"]["cells"]["role-2"]["access"] == "hidden"
        assert cell["tickets.query"]["cells"]["role-2"] == {"access": "write", "limits": ["sql: a single SELECT only"]}
        assert cell["files.fs.read"]["cells"]["role-2"]["limits"] == ["path: only /workspace and below"]
        assert {r["id"] for r in p["rules"]} == {"data_flow", "masked", "blocked", "injection", "signatures", "loops",
                                                 "budgets", "approval_timeout"}
        assert all(r["title"] and r["sentence"] and r["action"] for r in p["rules"])
        assert p["history"][0]["version"] == holder.version and p["history"][0]["ok"]
        pr = p["profiles"]
        assert pr["current"] == "balanced" and pr["names"] == ["strict", "balanced", "lenient"]
        flow = next(d for d in pr["diff"] if d["setting"] == "taint.block_flow.action")
        assert flow["values"] == {"strict": "block", "balanced": "block", "lenient": "ask a human"}
        assert pr["changes"]["balanced"] == [] or all(x["plain"] for x in pr["changes"]["balanced"])
        assert pr["changes"]["strict"] and {x["direction"] for x in pr["changes"]["strict"]} == {"stricter"}
        assert {"looser"} == {x["direction"] for x in pr["changes"]["lenient"]}


async def test_profile_switch_backs_up_reloads_and_enforces(monkeypatch, tmp_path):
    from fastmcp import Client
    from fastmcp.client.transports import StreamableHttpTransport

    from tollgate.gateway.keys import issue
    from tollgate.gateway.policy import DEFAULT_PATH

    repo_policy = DEFAULT_PATH.read_bytes()
    async with _policy_app(monkeypatch, tmp_path) as (c, app, holder):
        def factory(**kw):
            return httpx2.AsyncClient(transport=httpx2.ASGITransport(app=app), base_url="http://127.0.0.1", **kw)

        async def write(path):
            async with Client(StreamableHttpTransport("http://t/mcp/role-2/", auth=issue("role-2"),
                                                      httpx_client_factory=factory)) as m:
                r = await m.call_tool("files.fs.write", {"path": path, "content": "x"}, raise_on_error=False)
                return r.is_error

        assert not await write("/workspace/notes.txt")  # balanced: no limit on writes
        v0 = holder.version
        assert (await c.post("/console/api/policy/profile", json={"profile": "nope"})).status_code == 400
        assert (await c.post("/console/api/policy/profile", content=b"[1]")).status_code == 400
        r = (await c.post("/console/api/policy/profile", json={"profile": "strict"})).json()
        assert r["status"]["profile"] == "strict" and r["status"]["version"] != v0 and not r["status"]["modified"]
        assert Path(r["backup"]).read_bytes() == repo_policy and v0 in Path(r["backup"]).name
        assert (tmp_path / "policy.yaml").read_bytes() == (DEFAULT_PATH.parent / "policies" / "strict.yaml").read_bytes()
        assert await write("/workspace/notes.txt")  # strict: writes only under /workspace/out
        h = (await c.get("/console/api/policy")).json()["history"]
        assert h[0]["ok"] and h[0]["profile"] == "strict" and h[0]["version"] == r["status"]["version"]

        # a rejected edit is kept in history with its reason; the old policy stays in force
        bad = tmp_path / "policy.yaml"
        bad.write_text("mode: strict\nservers: {}\nroles: {role-1: {servers: {nope: {access: read}}}}\n")
        os.utime(bad, ns=(10**18, 10**18))
        p = (await c.get("/console/api/policy")).json()
        assert p["history"][0]["ok"] is False and "nope" in p["history"][0]["error"]
        assert p["status"]["version"] == r["status"]["version"] and p["status"]["last_error"]
        assert (tmp_path / "policy_history.jsonl").read_text().count("\n") >= 3  # TOLLGATE_AUDIT's directory
    assert DEFAULT_PATH.read_bytes() == repo_policy

    from tollgate.gateway.policy import load_policy  # history survives a restart
    assert load_policy(DEFAULT_PATH).history[-2]["ok"] is False


async def test_policy_api_needs_admin(monkeypatch, tmp_path):
    async with _policy_app(monkeypatch, tmp_path) as (_, app, _h):
        async with httpx2.AsyncClient(transport=httpx2.ASGITransport(app=app, client=("10.1.2.3", 5000)),
                                      base_url="http://127.0.0.1") as remote:
            assert (await remote.get("/console/api/policy")).status_code == 401
            assert (await remote.post("/console/api/policy/profile", json={"profile": "strict"})).status_code == 401


async def _access(c, holder, *changes, base=None):
    return await c.post("/console/api/policy/access", json={
        "base_version": base or holder.version, "changes": [{"role": r, "tool": t, "allowed": a} for r, t, a in changes]})


async def test_access_edit_writes_smallest_form(monkeypatch, tmp_path):
    import yaml

    from tollgate.gateway.policy import DEFAULT_PATH
    repo_policy = DEFAULT_PATH.read_bytes()
    async with _policy_app(monkeypatch, tmp_path) as (c, _, holder):
        v0 = holder.version
        r = await _access(c, holder, ("role-1", "github.pr.create", True), ("role-2", "files.fs.delete", True),
                          ("role-2", "files.fs.list", False))
        assert r.status_code == 200, r.text
        j = r.json()
        assert "Intern bot may now open a pull request (write, public destination)" in j["sentences"]
        assert "Support assistant may now delete a file (write)" in j["sentences"]
        assert "Support assistant can no longer list files" in j["sentences"] and len(j["sentences"]) == 3
        assert Path(j["backup"]).read_bytes() == repo_policy and v0 in Path(j["backup"]).name
        assert j["status"]["version"] == holder.version != v0 and j["status"]["modified"] is True
        p = yaml.safe_load((tmp_path / "policy.yaml").read_text(encoding="utf-8"))
        assert p["roles"]["role-1"]["servers"]["github"] == {"access": "rw"}
        assert p["roles"]["role-2"]["servers"]["files"] == {"tools": ["fs.read", "fs.write", "fs.delete"]}
        assert p["roles"]["role-2"]["constrain"] == {"files.fs.read": {"path": "/workspace/**"},
                                                     "tickets.query": {"sql": "select_only"}}
        assert p["roles"]["role-2"]["content"] == {"secrets": "redact"} and p["content"]["secrets"] == "block"
        h = (await c.get("/console/api/policy")).json()["history"][0]
        assert h["ok"] and h["note"] == "Edited in console by admin-token" and h["version"] == holder.version

        # all tools -> rw; only the read tools -> read; nothing -> the server key goes
        assert (await _access(c, holder, ("role-2", "files.fs.list", True))).status_code == 200
        assert yaml.safe_load((tmp_path / "policy.yaml").read_text())["roles"]["role-2"]["servers"]["files"] == {"access": "rw"}
        assert (await _access(c, holder, ("role-2", "github.pr.create", False))).status_code == 200
        assert yaml.safe_load((tmp_path / "policy.yaml").read_text())["roles"]["role-2"]["servers"]["github"] == {"access": "read"}
        assert (await _access(c, holder, ("role-1", "github.issues.read", False), ("role-1", "github.repo.read", False),
                              ("role-1", "github.pr.create", False))).status_code == 200
        assert "github" not in yaml.safe_load((tmp_path / "policy.yaml").read_text())["roles"]["role-1"]["servers"]
    assert DEFAULT_PATH.read_bytes() == repo_policy


async def test_access_edit_enforced_on_next_call(monkeypatch, tmp_path):
    from fastmcp import Client
    from fastmcp.client.transports import StreamableHttpTransport

    from tollgate.gateway.keys import issue
    async with _policy_app(monkeypatch, tmp_path) as (c, app, holder):
        def factory(**kw):
            return httpx2.AsyncClient(transport=httpx2.ASGITransport(app=app), base_url="http://127.0.0.1", **kw)

        async def names():
            async with Client(StreamableHttpTransport("http://t/mcp/role-1/", auth=issue("role-1"),
                                                      httpx_client_factory=factory)) as m:
                return {t.name for t in await m.list_tools()}

        assert "github.pr.create" not in await names()
        assert (await _access(c, holder, ("role-1", "github.pr.create", True))).status_code == 200
        assert "github.pr.create" in await names()
        m = (await c.get("/console/api/policy")).json()["matrix"]
        cell = {t["name"]: t for s in m["servers"] for t in s["tools"]}
        assert cell["github.pr.create"]["cells"]["role-1"]["access"] == "write"


async def test_access_edit_refusals(monkeypatch, tmp_path):
    async with _policy_app(monkeypatch, tmp_path) as (c, app, holder):
        before = (tmp_path / "policy.yaml").read_bytes()
        assert (await _access(c, holder, ("role-1", "github.pr.create", True), base="deadbeef")).status_code == 409
        assert (await c.post("/console/api/policy/access", json={"base_version": "x", "changes": []})).status_code == 400
        assert (await c.post("/console/api/policy/access", content=b"[1]")).status_code == 400
        for bad in [("role-9", "github.pr.create", True), ("role-1", "github.nope", True),
                    ("role-1", "github.pr.create", "yes"), ("role-1", "github.issues.read", True)]:  # last: no change
            assert (await _access(c, holder, bad)).status_code == 400, bad
        assert (tmp_path / "policy.yaml").read_bytes() == before
        # the file changed underneath (the admin's view is stale): 409 carries the new version
        old = holder.version
        (tmp_path / "policy.yaml").write_bytes(before + b"\n# edited by hand\n")
        os.utime(tmp_path / "policy.yaml", ns=(10**18, 10**18))
        stale = await _access(c, holder, ("role-1", "github.pr.create", True), base=old)
        assert stale.status_code == 409 and stale.json()["version"] == holder.version != old
        async with httpx2.AsyncClient(transport=httpx2.ASGITransport(app=app, client=("10.1.2.3", 5000)),
                                      base_url="http://127.0.0.1") as remote:
            r = await remote.post("/console/api/policy/access", json={"base_version": holder.version, "changes": [
                {"role": "role-1", "tool": "github.pr.create", "allowed": False}]})
            assert r.status_code == 401


def test_corrupt_peer_registry_is_never_overwritten(tmp_path, monkeypatch):
    p = tmp_path / "peers.json"
    monkeypatch.setenv("TOLLGATE_PEERS", str(p))
    peers.enroll(peers.enroll_token()["token"], "Ada", "ada-x1")
    p.write_text('{"peers": {"p1": ', encoding="utf-8")  # a torn write / bad hand edit
    assert peers.load() == {"peers": {}, "tokens": {}}   # reads fail closed (no peer, no key)
    with pytest.raises(RuntimeError, match="corrupt"):
        peers.enroll_token()
    assert p.read_text(encoding="utf-8") == '{"peers": {"p1": '
