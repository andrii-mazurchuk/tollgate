"""Edge API shapes (/edge/api/*): status, sessions, timeline, analytics, setup, scenario; loopback only."""
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


async def test_scenario_then_views(monkeypatch):
    async with _edge(monkeypatch) as (c, _):
        assert (await c.post("/edge/api/scenario/reset")).json() == {"ok": True}
        for step in ("3.1", "3.2", "3.3"):
            r = (await c.post(f"/edge/api/scenario/run/{step}")).json()
            assert r["pass"], r
        sc = (await c.get("/edge/api/scenario")).json()
        act3 = next(a for a in sc["acts"] if a["id"] == "3")
        assert act3["steps"][2]["result"]["pass"] and act3["steps"][2]["expected"].startswith("BLOCK")
        assert next(a for a in sc["acts"] if a["id"] == "4")["steps"][0]["operator"]

        st = (await c.get("/edge/api/status")).json()
        assert st["account"]["agent"] == "Support assistant" and st["policy"]["profile"] == "balanced"
        assert st["health"]["level"] == "alert" and st["health"]["message"] == "1 action blocked"
        assert (await c.get("/edge/api/status", params={"since": "9999"})).json()["health"]["level"] == "ok"

        sessions = (await c.get("/edge/api/sessions")).json()["sessions"]
        s = sessions[0]
        assert s["state"] == "untrusted+holds_private" and s["last_verdict"] == "block"
        assert s["tools"] == ["Read an issue", "Read a file from a repository", "Open a pull request"]
        assert s["label"].startswith("Scenario act 3") and s["active"]

        tl = (await c.get(f"/edge/api/sessions/{s['id']}")).json()["timeline"]
        assert [e["verdict"] for e in tl] == ["allow", "redact", "block"]
        assert tl[1]["text"]["result"]["original"].count("AKIA") == 1 and "[SECRET]" in tl[1]["text"]["result"]["sent"]
        assert tl[2]["explain"]["sentence"] == "Open a pull request: was blocked."
        assert [x["name"] for x in tl[2]["stages"]] == list(STAGES)
        assert tl[0]["explain"]["effect"].startswith("The session is now Untrusted")
        assert (await c.get("/edge/api/sessions/nope")).status_code == 404

        an = (await c.get("/edge/api/analytics")).json()
        assert an["blocked"] == 1 and an["masked"] == 1 and "taint.flow" in [r["rule"] for r in an["top_reasons"]]
        assert sum(sum(r[a] for a in ("allow", "redact", "approve", "block")) for r in an["series"]) == 3


async def test_setup_and_test_connection(monkeypatch):
    async with _edge(monkeypatch) as (c, _):
        s = (await c.get("/edge/api/setup")).json()
        assert s["mcp_url"] == "http://127.0.0.1:8080/mcp/role-2/" and s["key"].startswith("tg_role-2_")
        assert "…" in s["key_masked"] and s["key"] not in s["key_masked"]
        assert set(s["snippets"]) == {"Claude Code", "Cursor", "OpenAI SDK"} and "{KEY}" in s["snippets"]["Cursor"]
        t = (await c.get("/edge/api/setup/test")).json()
        assert t["ok"] and {"name": "github.pr.create", "plain": "Open a pull request"} in t["tools"]


async def test_edge_ui_served_and_local_only(monkeypatch):
    async with _edge(monkeypatch) as (c, app):
        assert (await c.get("/edge/")).status_code == 200
        async with httpx2.AsyncClient(transport=httpx2.ASGITransport(app=app, client=("10.1.2.3", 5000)),
                                      base_url="http://x") as remote:
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
