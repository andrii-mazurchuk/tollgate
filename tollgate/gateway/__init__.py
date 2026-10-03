import contextlib
import importlib
import posixpath
from pathlib import PurePosixPath

from fastmcp import FastMCP
from fastmcp.exceptions import ToolError
from fastmcp.server import create_proxy
from fastmcp.server.dependencies import get_http_headers
from fastmcp.server.middleware import Middleware
from fastmcp.server.providers.fastmcp_provider import FastMCPProvider
from fastmcp.server.transforms.namespace import Namespace
from starlette.applications import Starlette
from starlette.responses import JSONResponse
from starlette.routing import Mount

from tollgate.gateway import keys
from tollgate.gateway.policy import PolicyHolder


def build_gateway(github) -> FastMCP:
    """Tollgate gateway: proxies the github MCP under dotted tool names."""
    gw = FastMCP("tollgate")
    gw.mount(create_proxy(github), tool_names={
        "issues_read": "github.issues.read",
        "repo_read": "github.repo.read",
        "pr_create": "github.pr.create",
    })
    return gw


class Dotted(Namespace):
    """`issues_read` on server github -> `github.issues.read`."""

    def _transform_name(self, name: str) -> str:
        return f"{self._prefix}.{name.replace('_', '.')}"

    def _reverse_name(self, name: str) -> str | None:
        head = f"{self._prefix}."
        return name[len(head):].replace(".", "_") if name.startswith(head) else None


def tool_allowed(role_policy: dict, tool) -> bool:
    server, _, short = tool.name.partition(".")
    spec = (role_policy.get("servers") or {}).get(server)
    if not spec:
        return False
    if "tools" in spec:
        return short in spec["tools"]
    # ponytail: read/write from the server's own hints; admin override goes here when needed
    return spec.get("access") == "rw" or bool(tool.annotations and tool.annotations.read_only_hint)


def check_args(constraint: dict, args: dict) -> str | None:
    """Returns why the arguments break the constraint, or None."""
    for key, rule in constraint.items():
        if key == "to_domain":
            if not str(args.get("to", "")).endswith(rule):
                return f"recipient outside {rule}"
        elif rule == "select_only":
            sql = str(args.get(key, "")).strip().rstrip(";").strip()
            if not sql.upper().startswith("SELECT") or ";" in sql:
                return f"{key}: only a single SELECT is allowed"
        else:
            val = posixpath.normpath(str(args.get(key, "")))
            if not PurePosixPath(val).full_match(rule):
                return f"{key}: {val} outside {rule}"
    return None


class RoleGate(Middleware):
    """Per-role scoping. Reads the policy on every request; denies on call too (list filtering does not block)."""

    def __init__(self, role: str, policy: PolicyHolder, server: FastMCP):
        self.role, self.policy, self.server = role, policy, server

    def role_policy(self) -> dict:
        return (self.policy.data.get("roles") or {}).get(self.role) or {}

    async def on_list_tools(self, context, call_next):
        rp = self.role_policy()
        return [t for t in await call_next(context) if tool_allowed(rp, t)]

    async def on_call_tool(self, context, call_next):
        name, args = context.message.name, context.message.arguments or {}
        auth = get_http_headers(include={"authorization"}).get("authorization")
        ident = keys.from_header(auth)  # (role, key_id); None in-process (no HTTP)
        if auth and (not ident or ident[0] != self.role):
            raise ToolError(f"role.denied: key not bound to {self.role}")
        rp = self.role_policy()
        tool = await self.server.get_tool(name)
        if tool is None or not tool_allowed(rp, tool):
            raise ToolError(f"role.denied: {name} is not available to {self.role}")
        why = check_args((rp.get("constrain") or {}).get(name, {}), args)
        if why:
            raise ToolError(f"role.constraint: {name} {why}")
        return await call_next(context)


def load_sources(policy: PolicyHolder) -> dict[str, FastMCP]:
    return {n: importlib.import_module(s["mock"]).mcp for n, s in policy.data["servers"].items() if "mock" in s}


def build_role_server(role: str, policy: PolicyHolder, sources: dict[str, FastMCP] | None = None) -> FastMCP:
    """Mounts every source; the gate decides per request, so a policy swap changes the next tools/list."""
    srv = FastMCP(f"tollgate-{role}")
    for name, src in (sources or load_sources(policy)).items():
        srv.add_provider(FastMCPProvider(create_proxy(src)).wrap_transform(Dotted(name)))
    srv.add_middleware(RoleGate(role, policy, srv))
    return srv


def require_key(role: str, app):
    """ASGI guard: 401 unless the bearer key is valid and bound to this route's role."""
    async def guard(scope, receive, send):
        if scope["type"] == "http":
            auth = dict(scope["headers"]).get(b"authorization", b"").decode()
            ident = keys.from_header(auth)
            if not ident or ident[0] != role:
                return await JSONResponse({"error": "invalid key for this role"}, 401)(scope, receive, send)
        await app(scope, receive, send)
    return guard


def build_app(policy: PolicyHolder) -> Starlette:
    """/mcp/{role}/ per role in the policy. ponytail: roles fixed at startup; new roles need a restart."""
    sources = load_sources(policy)
    apps = {r: build_role_server(r, policy, sources).http_app(path="/") for r in policy.data["roles"]}

    @contextlib.asynccontextmanager
    async def lifespan(_):
        async with contextlib.AsyncExitStack() as stack:
            for a in apps.values():
                await stack.enter_async_context(a.router.lifespan_context(a))
            yield

    return Starlette(routes=[Mount(f"/mcp/{r}", app=require_key(r, a)) for r, a in apps.items()], lifespan=lifespan)
