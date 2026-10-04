"""Hand-issued keys (no peer) are refused at every door unless the policy sets allow_unenrolled_keys: true."""
import contextlib

import httpx2
import pytest

from tollgate.gateway import keys

pytestmark = pytest.mark.track_a

LIST = {"jsonrpc": "2.0", "id": 1, "method": "tools/list"}
CHAT = {"model": "qwen3:4b", "messages": [{"role": "user", "content": "Hi"}]}
HOOK = {"hook_event_name": "PreToolUse", "tool_name": "Read", "tool_input": {"file_path": "README.md"},
        "session_id": "s", "cwd": "."}


@contextlib.asynccontextmanager
async def _app(monkeypatch, flag):
    monkeypatch.setenv("TOLLGATE_UPSTREAM", "scripted")
    from tollgate.gateway import build_app
    from tollgate.gateway.policy import PolicyHolder, load_policy
    app = build_app(PolicyHolder({**load_policy().data, "allow_unenrolled_keys": flag}))
    async with app.router.lifespan_context(app):
        async with httpx2.AsyncClient(transport=httpx2.ASGITransport(app=app), base_url="http://127.0.0.1") as c:
            yield c


async def _codes(c) -> list[int]:
    h = {"Authorization": f"Bearer {keys.issue('role-2')}", "Accept": "application/json, text/event-stream"}
    return [(await c.post("/mcp/role-2/", headers=h, json=LIST)).status_code,
            (await c.post("/hook", headers=h, json=HOOK)).status_code,
            (await c.post("/v1/chat/completions", headers=h, json=CHAT)).status_code]


async def test_unenrolled_key_refused_by_default(monkeypatch):
    async with _app(monkeypatch, False) as c:
        assert await _codes(c) == [401, 401, 401]


async def test_unenrolled_key_accepted_with_flag(monkeypatch):
    async with _app(monkeypatch, True) as c:
        assert 401 not in await _codes(c)


def test_production_default_is_off_and_flag_is_validated():
    from tollgate.gateway import policy
    assert keys.from_header(f"Bearer {keys.issue('role-2')}") is None
    base = policy.load_policy().data
    assert "allow_unenrolled_keys" not in base  # shipped policy: off
    with pytest.raises(ValueError, match="allow_unenrolled_keys"):
        policy.validate({**base, "allow_unenrolled_keys": "yes"})
