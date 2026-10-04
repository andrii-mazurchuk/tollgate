"""Edge API shapes (/edge/api/*): status, sessions, timeline, analytics, setup; loopback only."""
import asyncio
import contextlib

import httpx2
import pytest

from tollgate.contract import STAGES

pytestmark = pytest.mark.track_a


@contextlib.asynccontextmanager
async def _edge(monkeypatch):  # not a fixture: lifespan enter/exit must run in the same task
    monkeypatch.setenv("TOLLGATE_T2", "off")
    monkeypatch.setenv("TOLLGATE_UPSTREAM", "scripted")
    from tollgate.gateway import build_app
    from tollgate.gateway.policy import load_policy

    app = build_app(load_policy())
    async with app.router.lifespan_context(app):
        async with httpx2.AsyncClient(transport=httpx2.ASGITransport(app=app), base_url="http://127.0.0.1:8080") as c:
            yield c, app


async def test_attack_then_views(monkeypatch):
    from tollgate import scenario
    async with _edge(monkeypatch) as (c, app):
        r = scenario.Runner(app)
        r.reset()
        for step in ("3.1", "3.2", "3.3"):
            res = await r.run(step)
            assert res["pass"], res
        assert (await c.get("/edge/api/scenario")).status_code == 404  # the edge Scenario view is gone

        st = (await c.get("/edge/api/status")).json()
        assert st["account"]["agent"] == "Support assistant" and st["policy"]["profile"] == "balanced"
        assert st["health"]["level"] == "alert" and st["health"]["message"] == "1 action blocked"
        assert (await c.get("/edge/api/status", params={"since": "9999"})).json()["health"]["level"] == "ok"

        sessions = (await c.get("/edge/api/sessions")).json()["sessions"]
        s = sessions[0]
        assert s["state"] == "untrusted+holds_private" and s["last_verdict"] == "block"
        assert s["tools"] == ["Read an issue", "Read a file from a repository", "Open a pull request"]
        assert s["active"]

        tl = (await c.get(f"/edge/api/sessions/{s['id']}")).json()["timeline"]
        assert [e["verdict"] for e in tl] == ["allow", "redact", "block"]
        assert tl[1]["text"]["result"]["original"].count("AKIA") == 1 and "[SECRET]" in tl[1]["text"]["result"]["sent"]
        assert tl[2]["explain"]["sentence"] == "Open a pull request: was blocked."
        assert [x["name"] for x in tl[2]["stages"]] == list(STAGES)
        assert tl[0]["explain"]["effect"].startswith("The session is now Untrusted")
        assert (await c.get("/edge/api/sessions/nope")).status_code == 404

        ov = (await c.get("/edge/api/overview", params={"range": "15m"})).json()
        assert ov["kpis"]["blocked"]["value"] >= 1 and ov["needs_look"][0]["action"] == "Data-flow rule: blocked"
        ev = (await c.get("/edge/api/events", params={"range": "15m", "action": "blocked"})).json()
        assert ev["items"][0]["session_id"] == s["id"] and {x["kind"] for x in ev["items"]} == {"blocked"}
        assert tl[2]["kind"] == "blocked" and tl[0]["kind"] is None


async def test_setup_and_test_connection(monkeypatch):
    async with _edge(monkeypatch) as (c, _):
        s = (await c.get("/edge/api/setup")).json()
        assert s["mcp_url"] == "http://127.0.0.1:8080/mcp/role-2/" and "key" not in s  # masked only
        assert s["key_masked"].startswith("tg_role-")
        assert s["peer"] is None and s["connect"] == "tollgate connect claude-code --role role-2 --peer <peer id>"
        assert set(s["snippets"]) == {"Claude Code", "Cursor", "OpenAI SDK"} and "{KEY}" in s["snippets"]["Cursor"]
        t = (await c.get("/edge/api/setup/test")).json()
        assert t["ok"] and {"name": "github.pr.create", "plain": "Open a pull request"} in t["tools"]


async def test_edge_ui_served_and_local_only(monkeypatch):
    async with _edge(monkeypatch) as (c, app):
        assert (await c.get("/edge/")).status_code == 200
        async with httpx2.AsyncClient(transport=httpx2.ASGITransport(app=app, client=("10.1.2.3", 5000)),
                                      base_url="http://127.0.0.1") as remote:
            assert (await remote.get("/edge/api/setup")).status_code == 403


async def test_audit_write_notifies_listeners():
    from tollgate.contract import AuditEvent
    from tollgate.gateway import audit
    q = asyncio.Queue()
    audit.LISTENERS.add(q)
    try:
        audit.write(AuditEvent(ts="2026-10-03T00:00:00.000Z", role="role-2", key_id="k", door="tool", verdict="allow"))
        assert q.get_nowait().startswith("t_")
    finally:
        audit.LISTENERS.discard(q)


async def test_edge_api_refuses_rebinding_and_cross_origin(monkeypatch):
    """DNS rebinding: a foreign page resolving to 127.0.0.1 sends its own Host; a cross-site POST sends its Origin."""
    async with _edge(monkeypatch) as (c, _):
        assert (await c.get("/edge/api/setup", headers={"Host": "attacker.example:8110"})).status_code == 403
        assert (await c.get("/edge/api/setup", headers={"Host": "localhost:8107"})).status_code == 200
        assert (await c.get("/edge/api/setup", headers={"Host": "[::1]:8107"})).status_code == 200
        bad = {"Origin": "http://attacker.example", "Content-Type": "application/json"}
        assert (await c.post("/edge/api/settings", headers=bad, content=b"{}")).status_code == 403
        ok = {"Origin": "http://127.0.0.1:8080", "Content-Type": "application/json"}
        assert (await c.post("/edge/api/settings", headers=ok, content=b"{}")).status_code == 200
        monkeypatch.setenv("TOLLGATE_ALLOWED_HOSTS", "edge.corp")
        assert (await c.get("/edge/api/setup", headers={"Host": "edge.corp"})).status_code == 200


async def test_setup_shows_this_laptops_peer(monkeypatch):
    from tollgate.gateway import peers
    from tollgate.gateway.policy import load_policy
    pid = peers.enroll(peers.enroll_token()["token"], "Ada", "ada-x1")
    peers.set_roles(pid, ["role-2"])
    monkeypatch.setenv("TOLLGATE_EDGE_KEY", peers.mint(pid, "role-2", load_policy().data["roles"]))
    async with _edge(monkeypatch) as (c, _):
        s = (await c.get("/edge/api/setup")).json()
        assert s["peer"] == {"id": pid, "device": "ada-x1", "owner": "Ada", "roles": ["role-2"], "revoked": False}
        assert s["connect"].endswith(f"--peer {pid}")
        assert (await c.get("/edge/api/setup/test")).json()["ok"]


async def test_setup_test_explains_a_rejected_unenrolled_key(monkeypatch):
    from tollgate.gateway import keys
    monkeypatch.setattr(keys, "unenrolled_ok", lambda data: False)  # the production default
    async with _edge(monkeypatch) as (c, _):
        assert (await c.get("/edge/api/setup")).json()["unenrolled_ok"] is False
        t = (await c.get("/edge/api/setup/test")).json()
        assert not t["ok"] and "allow_unenrolled_keys" in t["error"] and "tollgate connect" in t["error"]
