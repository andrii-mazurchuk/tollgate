import pytest
from fastmcp import Client

pytestmark = [pytest.mark.track_a]


async def test_m0_proxy_passthrough():
    """M0 gate: a role server with full access to the mock github lists exactly its tools under dotted names, and a
    tools/call round-trips unchanged (in-memory fastmcp Client)."""
    from mocks.github import mcp as github
    from tollgate.gateway import build_role_server
    from tollgate.gateway.policy import PolicyHolder, validate

    policy = PolicyHolder(validate({"servers": {"github": {"mock": "mocks.github"}},
                                    "roles": {"dev": {"servers": {"github": {"access": "rw"}}}}}))
    async with Client(github) as src, Client(build_role_server("dev", policy)) as gw:
        src_tools = {t.name: t for t in await src.list_tools()}
        gw_tools = {t.name: t for t in await gw.list_tools()}

        assert set(src_tools) == {"issues_read", "repo_read", "pr_create"}
        assert set(gw_tools) == {"github.issues.read", "github.repo.read", "github.pr.create"}
        assert gw_tools["github.issues.read"].annotations.read_only_hint is True
        assert gw_tools["github.pr.create"].annotations.read_only_hint is False

        args = {"repo": "acme/website", "number": 12}
        direct = await src.call_tool("issues_read", args)
        proxied = await gw.call_tool("github.issues.read", args)
        assert proxied.content[0].text == direct.content[0].text
        assert "acme/payroll" in proxied.content[0].text
