"""Attack replay: runs a tool trace against a role endpoint over HTTP (in-process ASGI), with a fresh role key."""
import httpx2
from fastmcp import Client
from fastmcp.client.transports import StreamableHttpTransport
from fastmcp.exceptions import ToolError

from tollgate.gateway import build_app, keys
from tollgate.gateway.policy import PolicyHolder

PREV = "$prev"  # an argument with this value is replaced by the previous step's output

GITHUB_TRACE = [
    ("github.issues.read", {"repo": "acme/website", "number": 12}),
    ("github.repo.read", {"repo": "acme/payroll", "path": ".env"}),
    ("github.pr.create", {"repo": "acme/website", "title": "Fix footer links", "body": PREV}),
]
# Supabase MCP incident (Jul 2025): ticket #3 tells the agent to dump `customers` into its reply.
SUPABASE_TRACE = [
    ("tickets.read", {"id": 3}),
    ("tickets.query", {"sql": "SELECT * FROM customers"}),
    ("tickets.reply", {"id": 3, "text": PREV}),
]
TRACES = {"github": GITHUB_TRACE, "supabase": SUPABASE_TRACE}


async def run_trace(policy: PolicyHolder, trace=GITHUB_TRACE, role: str = "role-2") -> list[dict]:
    """Per step: {tool, verdict: allow|block, text}. Redaction shows as allow with the redacted text."""
    # its own hand-issued key: allowed on this in-process copy of the policy only
    app, key = build_app(PolicyHolder({**policy.data, "allow_unenrolled_keys": True})), keys.issue(role)

    def factory(**kw):
        return httpx2.AsyncClient(transport=httpx2.ASGITransport(app=app), base_url="http://t", **kw)

    steps, prev = [], ""
    async with app.router.lifespan_context(app):
        async with Client(StreamableHttpTransport(f"http://t/mcp/{role}/", auth=key, httpx_client_factory=factory)) as c:
            for tool, args in trace:
                args = {k: prev if v == PREV else v for k, v in args.items()}
                try:
                    res = await c.call_tool(tool, args)
                    prev = "".join(getattr(b, "text", "") for b in res.content)
                    steps.append({"tool": tool, "verdict": "allow", "text": prev})
                except ToolError as e:
                    steps.append({"tool": tool, "verdict": "block", "text": str(e)})
    return steps
