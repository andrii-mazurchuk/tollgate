import httpx2
import pytest
from fastmcp import Client
from fastmcp.client.transports import StreamableHttpTransport
from fastmcp.exceptions import ToolError

pytestmark = [pytest.mark.track_a]


async def test_ac02_role_scoping():
    """AC2: /mcp/role-1 lists only role-1's tools; calling any other tool, or using role-1's key on /mcp/role-2, is rejected."""
    from tollgate.gateway import build_app
    from tollgate.gateway.keys import issue
    from tollgate.gateway.policy import load_policy

    app = build_app(load_policy())
    k1, k2 = issue("role-1"), issue("role-2")

    def factory(**kw):
        return httpx2.AsyncClient(transport=httpx2.ASGITransport(app=app), base_url="http://127.0.0.1", **kw)

    def client(role, key):
        return Client(StreamableHttpTransport(f"http://t/mcp/{role}/", auth=key, httpx_client_factory=factory))

    async with app.router.lifespan_context(app):
        async with client("role-1", k1) as c:
            assert {t.name for t in await c.list_tools()} == {"github.issues.read", "github.repo.read"}
            assert "acme/payroll" in (await c.call_tool("github.issues.read", {"repo": "acme/website", "number": 12})).data
            with pytest.raises(ToolError):
                await c.call_tool("github.pr.create", {"repo": "acme/website", "title": "t", "body": "b"})
            with pytest.raises(ToolError):
                await c.call_tool("tickets.query", {"sql": "SELECT 1"})

        async with client("role-2", k2) as c:
            assert "github.pr.create" in {t.name for t in await c.list_tools()}

        async with factory() as raw:
            body = {"jsonrpc": "2.0", "id": 1, "method": "tools/list"}
            hdr = {"accept": "application/json, text/event-stream"}
            assert (await raw.post("/mcp/role-2/", json=body, headers={**hdr, "authorization": f"Bearer {k1}"})).status_code == 401
            assert (await raw.post("/mcp/role-1/", json=body, headers=hdr)).status_code == 401
            assert (await raw.post("/mcp/role-1/", json=body, headers={**hdr, "authorization": f"Bearer {k1}x"})).status_code == 401
