"""Real upstream MCP servers (docs/connectivity.md): `command:` (stdio) and `url:` (HTTP) next to `mock:`, fronted
with every check unchanged; `${VAR}` expansion; an unreachable upstream degrades instead of crashing the hub."""
import contextlib
import socket
import sys
import textwrap
import threading
import time

import httpx2
import pytest
import uvicorn
from fastmcp import Client, FastMCP
from fastmcp.exceptions import ToolError
from mcp.types import ToolAnnotations

from tollgate.gateway import UPSTREAMS, build_app, build_role_server, connect_upstreams, load_sources, taint
from tollgate.gateway.policy import PolicyHolder, validate

pytestmark = pytest.mark.track_a

UPSTREAM = textwrap.dedent('''
    import os
    from fastmcp import FastMCP
    from mcp.types import ToolAnnotations
    mcp = FastMCP("up")

    @mcp.tool(annotations=ToolAnnotations(readOnlyHint=True))
    def fs_read(path: str) -> str:
        """Read a file."""
        return f"content of {path} {os.environ.get('UP_TAG', '')}"

    @mcp.tool(annotations=ToolAnnotations(readOnlyHint=False))
    def pr_create(title: str) -> str:
        """Open a pull request."""
        return f"opened {title}"

    if __name__ == "__main__":
        mcp.run(show_banner=False)
''')


def _free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


@pytest.fixture
def http_upstream():
    web = FastMCP("web")

    @web.tool(annotations=ToolAnnotations(readOnlyHint=True))
    def search(q: str) -> str:
        """Search the web."""
        return f"results for {q}"

    @web.tool(annotations=ToolAnnotations(readOnlyHint=False))
    def post(text: str) -> str:
        """Post publicly."""
        return "posted"

    port = _free_port()
    server = uvicorn.Server(uvicorn.Config(web.http_app(path="/mcp"), host="127.0.0.1", port=port, log_level="warning"))
    t = threading.Thread(target=server.run, daemon=True)
    t.start()
    for _ in range(100):
        if server.started:
            break
        time.sleep(0.05)
    yield f"http://127.0.0.1:{port}/mcp"
    server.should_exit = True
    t.join(5)


@pytest.fixture
def policy(tmp_path, monkeypatch, http_upstream):
    script = tmp_path / "up.py"
    script.write_text(UPSTREAM, encoding="utf-8")
    monkeypatch.setenv("TG_UP_TAG", "tag-from-env")
    monkeypatch.setenv("TG_WEB_TOKEN", "s3cret")
    taint.reset("local")
    return PolicyHolder(validate({
        "servers": {
            "up": {"command": sys.executable, "args": [str(script)], "env": {"UP_TAG": "${TG_UP_TAG}"}},
            "web": {"url": http_upstream, "headers": {"Authorization": "Bearer ${TG_WEB_TOKEN}"}},
            "dead": {"url": f"http://127.0.0.1:{_free_port()}/mcp"},
            "files": {"mock": "mocks.files"},
        },
        "roles": {"dev": {"servers": {"up": {"access": "rw"}, "web": {"access": "read"}, "dead": {"access": "rw"},
                                      "files": {"access": "read"}},
                          "constrain": {"up.fs.read": {"path": "/workspace/**"}}}},
        "labels": {"up.fs.read": ["untrusted_source", "private_data"], "up.pr.create": ["public_sink"]},
        "taint": {"enabled": True, "block_flow": {"from": "private_data", "to": "public_sink", "action": "block"}},
    }))


@contextlib.asynccontextmanager
async def _role(policy):
    sources = load_sources(policy)
    async with contextlib.AsyncExitStack() as stack:
        await connect_upstreams(stack, sources, timeout=5)
        async with Client(build_role_server("dev", policy, sources)) as c:
            yield c, sources


async def test_upstreams_filtered_checked_and_degraded(policy):
    async with _role(policy) as (c, sources):
        names = {t.name for t in await c.list_tools()}
        # stdio + HTTP tools under `<server>.<tool>`; web is read-only for this role; the dead one lists nothing
        assert {"up.fs.read", "up.pr.create", "web.search", "files.fs.read"} <= names
        assert "web.post" not in names and not any(n.startswith("dead.") for n in names)
        assert UPSTREAMS["up"]["reachable"] and UPSTREAMS["web"]["reachable"]
        assert UPSTREAMS["dead"]["reachable"] is False and UPSTREAMS["dead"]["error"]
        assert await sources["dead"].list_tools() == []  # console/edge see an empty server, not a crash

        r = await c.call_tool("up.fs.read", {"path": "/workspace/a.txt"})
        assert "content of /workspace/a.txt tag-from-env" in r.content[0].text  # env expanded into the stdio child
        assert "results for x" in (await c.call_tool("web.search", {"q": "x"})).content[0].text  # header expanded
        with pytest.raises(ToolError, match="role.constraint"):
            await c.call_tool("up.fs.read", {"path": "/etc/passwd"})
        with pytest.raises(ToolError, match="role.denied"):
            await c.call_tool("web.post", {"text": "x"})
        with pytest.raises(ToolError, match="taint.flow"):  # label on an upstream tool drives taint
            await c.call_tool("up.pr.create", {"title": "leak"})


async def test_app_starts_with_dead_upstream_and_reports_it(policy):
    app = build_app(policy)
    async with app.router.lifespan_context(app):
        async with httpx2.AsyncClient(transport=httpx2.ASGITransport(app), base_url="http://t") as h:
            up = (await h.get("/healthz")).json()["upstreams"]
            assert up["up"]["reachable"] and up["web"]["reachable"] and up["dead"]["reachable"] is False
            assert "s3cret" not in str(up)  # only the target, never headers/env
            srv = {s["name"]: s for s in (await h.get("/edge/api/agent")).json()["servers"]}
    assert srv["dead"]["unreachable"] and not srv["dead"]["reachable"] and not srv["up"]["unreachable"]


def test_missing_env_var_is_a_clear_startup_error(monkeypatch):
    monkeypatch.delenv("TG_NOPE", raising=False)
    p = PolicyHolder(validate({"servers": {"gh": {"url": "https://x/mcp", "headers": {"A": "Bearer ${TG_NOPE}"}}},
                               "roles": {}}))
    with pytest.raises(ValueError, match=r"servers\.gh\.headers\.A: environment variable TG_NOPE is not set"):
        load_sources(p)


@pytest.mark.parametrize("bad", [
    {"mock": "mocks.files", "url": "https://x"}, {}, {"url": "ftp://x"}, {"url": "https://x", "transport": "ws"},
    {"command": "x", "args": "a b"}, {"command": "x", "env": {"A": 1}}, {"command": "x", "headers": {}},
    {"url": "https://x", "headers": ["a"]},
])
def test_server_shape_validated(bad):
    with pytest.raises(ValueError, match="servers.s"):
        validate({"servers": {"s": bad}, "roles": {}})
