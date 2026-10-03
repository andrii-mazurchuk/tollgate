import copy
import json

import pytest

from tests.acceptance.door_stub import ask, door

pytestmark = [pytest.mark.track_a]
URL = "/v1/chat/completions"


def _events(tmp_path):
    return [json.loads(x) for x in (tmp_path / "events.jsonl").read_text(encoding="utf-8").splitlines()]


async def test_ac11_budget_429(tmp_path, monkeypatch):
    """AC11: a role over roles.<role>.budget.tokens_per_day gets 429 budget.exceeded; usage shows on /admin/budget."""
    from tollgate.gateway.keys import issue
    from tollgate.gateway.policy import load_policy

    p = copy.deepcopy(load_policy().data)
    p["roles"]["role-1"].update(models=["m"], budget={"tokens_per_day": 1000})
    p["roles"]["role-2"].update(models=["m"], budget={"tokens_per_day": 10**6})
    app, client = door(p, monkeypatch, tmp_path)
    k1, k2 = ({"authorization": f"Bearer {issue(r)}"} for r in ("role-1", "role-2"))
    async with app.router.lifespan_context(app), client() as c:
        for _ in range(2):  # 600 + 600: the second call is admitted (600 < 1000) and overshoots
            assert (await c.post(URL, json=ask("m", "hi"), headers=k1)).status_code == 200
        r = await c.post(URL, json=ask("m", "hi"), headers=k1)
        assert r.status_code == 429 and r.json()["error"]["code"] == "budget.exceeded"
        assert (await c.post(URL, json=ask("m", "hi"), headers=k2)).status_code == 200  # budgets are per role

        b = (await c.get("/admin/budget")).json()
        assert b["role-1"] == {"used": 1200, "limit": 1000}
        assert b["role-2"] == {"used": 600, "limit": 10**6}

    assert any(e["reasons"] and e["reasons"][0]["rule"] == "budget.exceeded" for e in _events(tmp_path))


async def test_ac11_loop_cutoff(tmp_path, monkeypatch):
    """AC11: the same key + tool + args beyond loops.max_identical_calls in a row is cut off; a different call resets."""
    monkeypatch.setenv("TOLLGATE_AUDIT", str(tmp_path / "events.jsonl"))
    from fastmcp import Client
    from fastmcp.exceptions import ToolError

    from tollgate.gateway import build_role_server
    from tollgate.gateway.policy import PolicyHolder, load_policy

    p = copy.deepcopy(load_policy().data)
    p["loops"] = {"max_identical_calls": 3}
    same = {"repo": "acme/website", "number": 12}
    async with Client(build_role_server("role-1", PolicyHolder(p))) as c:
        for _ in range(3):
            await c.call_tool("github.issues.read", same)
        with pytest.raises(ToolError, match="loop.cutoff"):
            await c.call_tool("github.issues.read", same)
        await c.call_tool("github.issues.read", {"repo": "acme/website", "number": 13})  # different args: reset
        await c.call_tool("github.issues.read", same)

    assert [e["reasons"][0]["rule"] for e in _events(tmp_path) if e["verdict"] == "block"] == ["loop.cutoff"]
