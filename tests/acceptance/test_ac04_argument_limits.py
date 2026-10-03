import pytest
from fastmcp import Client
from fastmcp.exceptions import ToolError

pytestmark = [pytest.mark.track_a]


async def test_ac04_argument_limits():
    """AC4: SELECT passes and DELETE is blocked on the same tool; a path outside the glob is blocked."""
    from tollgate.gateway import build_role_server
    from tollgate.gateway.policy import load_policy

    async with Client(build_role_server("role-2", load_policy())) as c:
        rows = (await c.call_tool("tickets.query", {"sql": "SELECT id FROM tickets"})).data
        assert rows
        for bad in ["DELETE FROM tickets", "SELECT 1; DROP TABLE tickets", "  delete from faq"]:
            with pytest.raises(ToolError):
                await c.call_tool("tickets.query", {"sql": bad})
        assert (await c.call_tool("tickets.query", {"sql": "select count(*) from tickets"})).data

        assert (await c.call_tool("files.fs.read", {"path": "/workspace/a.txt"})).data
        for bad in ["/etc/passwd", "/workspace/../etc/passwd"]:
            with pytest.raises(ToolError):
                await c.call_tool("files.fs.read", {"path": bad})
