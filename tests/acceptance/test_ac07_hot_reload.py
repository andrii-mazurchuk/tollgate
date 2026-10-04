import os

import httpx2
import pytest
from fastmcp import Client
from fastmcp.client.transports import StreamableHttpTransport

pytestmark = [pytest.mark.track_a]

T0 = 1_000_000_000_000_000_000


def _write(path, text, bump):
    path.write_text(text, encoding="utf-8")
    os.utime(path, ns=(T0 + bump, T0 + bump))  # coarse mtime on some filesystems: force a visible change


async def test_ac07_hot_reload(tmp_path, monkeypatch):
    """AC7: A policy edit applies on the next call without restart; an invalid file is rejected and the old policy kept."""
    monkeypatch.setenv("TOLLGATE_AUDIT", str(tmp_path / "events.jsonl"))
    from tollgate.mocks.github import PRS
    from tollgate.gateway import build_app
    from tollgate.gateway.keys import issue
    from tollgate.gateway.policy import DEFAULT_PATH, load_policy
    from tollgate.gateway.replay import run_trace

    src = DEFAULT_PATH.read_text(encoding="utf-8")
    path = tmp_path / "policy.yaml"
    _write(path, src, 0)
    holder = load_policy(path)
    v0 = holder.status()["version"]
    assert holder.status()["last_error"] is None

    app, key = build_app(holder), issue("role-1")

    def factory(**kw):
        return httpx2.AsyncClient(transport=httpx2.ASGITransport(app=app), base_url="http://127.0.0.1", **kw)

    async with app.router.lifespan_context(app):
        async with Client(StreamableHttpTransport("http://t/mcp/role-1/", auth=key, httpx_client_factory=factory)) as c:
            assert {t.name for t in await c.list_tools()} == {"github.issues.read", "github.repo.read"}

            # role tools: role-1 gains files.fs.read on the next tools/list, same app
            edited = src.replace("      github: { access: read }\n",
                                 "      github: { access: read }\n      files: { tools: [fs.read] }\n", 1)
            assert edited != src
            _write(path, edited, 1)
            assert {t.name for t in await c.list_tools()} == {"github.issues.read", "github.repo.read", "files.fs.read"}
            assert holder.status()["version"] != v0

            # invalid YAML: old policy kept, error visible
            _write(path, "roles: [unclosed\n", 2)
            assert "files.fs.read" in {t.name for t in await c.list_tools()}
            assert holder.status()["last_error"]["message"]
            # semantically invalid (unknown server) is rejected too
            _write(path, edited.replace("files: { tools: [fs.read] }", "nope: { access: read }"), 3)
            assert "files.fs.read" in {t.name for t in await c.list_tools()}
            assert "nope" in holder.status()["last_error"]["message"]

        async with factory() as raw:
            h = (await raw.get("/healthz")).json()
            assert h["policy"]["last_error"] and {"role-1", "role-2"} <= set(h["roles"])
            assert (await raw.get("/admin/taint")).status_code == 200

    # taint: flipping enabled changes the next replay verdict
    PRS.clear()
    _write(path, edited, 4)
    assert [s["verdict"] for s in await run_trace(holder)] == ["allow", "allow", "block"]
    assert holder.status()["last_error"] is None
    _write(path, edited.replace("  enabled: true", "  enabled: false"), 5)
    assert [s["verdict"] for s in await run_trace(holder)] == ["allow", "allow", "allow"]
    PRS.clear()


async def test_ac01_app_serves_healthz_and_roles():
    """AC1 (in-process part): build_app from the policy file serves /healthz and mounts every role (401 without a key)."""
    from tollgate.gateway import build_app
    from tollgate.gateway.policy import load_policy

    app = build_app(load_policy())
    async with app.router.lifespan_context(app):
        async with httpx2.AsyncClient(transport=httpx2.ASGITransport(app=app), base_url="http://127.0.0.1") as raw:
            h = (await raw.get("/healthz")).json()
            assert h["ok"] and h["policy"]["version"] and set(h["sources"]) == {"github", "tickets", "files"}
            assert set(h["roles"]) == {"role-1", "role-2"}
            for role in h["roles"]:
                assert (await raw.post(f"/mcp/{role}/", json={})).status_code == 401
