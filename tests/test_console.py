"""Peer registry (enroll once, roles, mint, revoke) and the server console API (/console/api/*)."""
import contextlib
import json
from datetime import datetime, timedelta, timezone

import httpx2
import pytest

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
    assert keys.from_header(f"Bearer {keys.issue('role-2')}")  # legacy keys keep working
    assert keys.from_header(f"Bearer {keys.issue('role-2', 'pabcd-1')}") is None  # unknown peer


@contextlib.asynccontextmanager
async def _app(monkeypatch):
    monkeypatch.setenv("TOLLGATE_UPSTREAM", "scripted")
    from tollgate.gateway import build_app
    from tollgate.gateway.policy import load_policy

    app = build_app(load_policy())
    async with app.router.lifespan_context(app):
        async with httpx2.AsyncClient(transport=httpx2.ASGITransport(app=app), base_url="http://127.0.0.1:8080") as c:
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
        assert st["health"]["message"] == "1 attack stopped" and st["admin"] == "loopback"
        assert set(st) == {"health", "admin", "policy", "feed", "app_version"}

        ov = (await c.get("/console/api/overview", params={"range": "15m"})).json()
        k = ov["kpis"]
        assert k["checked"]["value"] == 4 and k["blocked"]["value"] == 1 and k["attacks"]["value"] == 1
        assert k["peers_online"]["value"] == 1
        assert ov["by_role"] == [{"role": "role-2", "agent": "Support assistant", "count": 1}]
        assert ov["by_reason"][0]["count"] == 1 and ov["series"] and ov["bucket_s"]
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
                                      base_url="http://x") as remote:
            assert (await remote.get("/console/api/peers")).status_code == 401
            assert (await remote.post("/console/api/enroll-token")).status_code == 401
            from tollgate.gateway.approvals import ADMIN_DEV_TOKEN
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
