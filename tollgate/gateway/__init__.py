from fastmcp import FastMCP
from fastmcp.server import create_proxy


def build_gateway(github) -> FastMCP:
    """Tollgate gateway: proxies the github MCP under dotted tool names."""
    gw = FastMCP("tollgate")
    gw.mount(create_proxy(github), tool_names={
        "issues_read": "github.issues.read",
        "repo_read": "github.repo.read",
        "pr_create": "github.pr.create",
    })
    return gw
