"""Console Overview access map: GET /console/api/map (peer -> agent -> server traffic with blocked shares)."""
from datetime import datetime, timezone

import httpx2
import pytest

from tests.test_console import _app
from tollgate.console import access_map as console_map
from tollgate.gateway import peers

NOW = datetime(2026, 10, 4, 10, 0, tzinfo=timezone.utc)


@pytest.fixture(autouse=True)
def _peers_to_tmp(tmp_path, monkeypatch):
    monkeypatch.setenv("TOLLGATE_PEERS", str(tmp_path / "peers.json"))


def ev(sec, key, role, tool, verdict="allow", door="tool", source=None):
    return {"ts": f"2026-10-04T09:{sec // 60:02d}:{sec % 60:02d}Z", "key_id": key, "session_id": key, "role": role,
            "tool": tool, "door": door, "source": source or tool.partition(".")[0], "verdict": verdict,
            "trace_id": f"t{sec}"}


def test_map_counts_blocked_shares_and_buckets():
    pid = peers.enroll(peers.enroll_token()["token"], "Ada", "ada-x1")
    peers.set_roles(pid, ["role-2"])
    idle = peers.enroll(peers.enroll_token()["token"], "Bob", "bob-mac")
    k = f"{pid}-1"
    evs = [ev(1, k, "role-2", "files.fs.read"), ev(2, k, "role-2", "tickets.get"),
           ev(3, k, "role-2", "tickets.post", "block"), ev(4, k, "role-2", "builtin.Bash", door="hook", source="builtin"),
           ev(5, k, "role-2", "qwen3:1.7b", door="model", source="model"),
           ev(6, "legacy1", "role-1", "files.fs.read", "block")]
    m = console_map.build(evs, "1h", peers.load(), ["role-1", "role-2"], NOW)
    P = {p["id"]: p for p in m["peers"]}
    assert P[pid]["calls"] == 5 and P[pid]["blocked"] == 1 and P[pid]["label"] == "ada-x1 · Ada"
    assert P[idle]["calls"] == 0  # enrolled but silent peers still show
    assert P["unenrolled"]["label"] == "Unenrolled" and P["unenrolled"]["blocked"] == 1
    assert {s["id"]: s["label"] for s in m["servers"]} == {
        "files": "files", "tickets": "tickets", "builtins": "Agent built-ins", "model": "Model"}
    L = {(x["from"], x["to"]): x for x in m["links"]}
    t = L["r:role-2", "s:tickets"]
    assert (t["calls"], t["blocked"]) == (2, 1) and t["last_blocked"]["trace_id"] == "t3" and t["last_blocked"]["session_id"] == k
    assert L[f"p:{pid}", "r:role-2"]["calls"] == 5 and L[f"p:{pid}", "r:role-2"]["blocked"] == 1
    assert L["p:unenrolled", "r:role-1"]["blocked"] == 1
    assert sum(x["calls"] for x in m["paths"]) == 6
    assert [s["id"] for s in m["sessions"]["*"]] == ["legacy1", k] and m["sessions"]["s:tickets"][0]["blocked"] == 1
    assert console_map.build(evs, "15m", peers.load(), [], NOW)["links"] == []  # out of range


async def test_map_endpoint_and_admin(monkeypatch):
    async with _app(monkeypatch) as (c, app):
        m = (await c.get("/console/api/map", params={"range": "all"})).json()
        assert set(m) >= {"peers", "roles", "servers", "links", "paths", "sessions"}
        assert {r["role"] for r in m["roles"]} >= {"role-1", "role-2"}
        async with httpx2.AsyncClient(transport=httpx2.ASGITransport(app=app, client=("10.1.2.3", 5000)),
                                      base_url="http://127.0.0.1") as remote:
            assert (await remote.get("/console/api/map")).status_code == 401
