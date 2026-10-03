import pytest
from fastmcp import Client
from fastmcp.exceptions import ToolError

pytestmark = [pytest.mark.track_a]


async def test_ac03_exact_tools():
    """AC3: An exact tool list (tools: [...]) is honoured: excluded tools are absent from tools/list and rejected on call."""
    from tollgate.gateway import build_role_server
    from tollgate.gateway.policy import load_policy

    async with Client(build_role_server("role-2", load_policy())) as c:
        names = {t.name for t in await c.list_tools()}
        assert {"files.fs.list", "files.fs.read", "files.fs.write"} <= names
        assert "files.fs.delete" not in names
        assert {"github.pr.create", "tickets.query", "tickets.reply"} <= names
        with pytest.raises(ToolError):
            await c.call_tool("files.fs.delete", {"path": "/workspace/a.txt"})
        assert "/workspace/a.txt" in (await c.call_tool("files.fs.list", {"path": "/workspace"})).data
