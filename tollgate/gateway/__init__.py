import contextlib
import hashlib
import json
import time
from datetime import datetime, timezone
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
from fastmcp.tools.base import ToolResult
from mcp.types import TextContent
from starlette.applications import Starlette
from starlette.responses import JSONResponse
from starlette.routing import Mount, Route

from tollgate.content import scan
from tollgate.contract import SEVERITY, AuditEvent, Reason, Verdict
from tollgate.gateway import audit, keys, model_door, taint
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


def content_policy(data: dict, role_policy: dict) -> dict:
    """roles.<role>.content overrides keys of the global content section (A's section; B's stays untouched)."""
    return {**(data.get("content") or {}), **(role_policy.get("content") or {})}


def apply_verdict(ev: AuditEvent, v: Verdict, point: str) -> None:
    """Folds a content verdict into the event; raises on block/approve. Keeps reasons of flagged allows."""
    ev.reasons += v.reasons
    ev.transforms += [t for t in v.transforms if t not in ev.transforms]
    ev.t2_score = v.t2_score if v.t2_score is not None else ev.t2_score
    for tier, ms in v.latency_ms.items():
        ev.latency_ms[tier] = round(ev.latency_ms.get(tier, 0) + ms, 3)
    if SEVERITY[v.action] > SEVERITY[ev.verdict]:
        ev.verdict, ev.scan_point = v.action, point
    if v.action in ("block", "approve"):  # approve not built yet: treated as block
        raise ToolError(f"content: {v.action} at {point}: " + "; ".join(f"{r.rule} ({r.detail})" for r in v.reasons))


class RoleGate(Middleware):
    """Per-role scoping. Reads the policy on every request; denies on call too (list filtering does not block)."""

    def __init__(self, role: str, policy: PolicyHolder, server: FastMCP):
        self.role, self.policy, self.server = role, policy, server
        self.last: dict[str, tuple[str, int]] = {}  # key_id -> (last call signature, times in a row)

    def role_policy(self) -> dict:
        return (self.policy.data.get("roles") or {}).get(self.role) or {}

    async def on_list_tools(self, context, call_next):
        rp = self.role_policy()
        return [t for t in await call_next(context) if tool_allowed(rp, t)]

    async def on_call_tool(self, context, call_next):
        name, args = context.message.name, context.message.arguments or {}
        auth = get_http_headers(include={"authorization"}).get("authorization")
        ident = keys.from_header(auth)  # (role, key_id); None in-process (no HTTP)
        key_id = ident[1] if ident else "local"
        args_json = json.dumps(args, ensure_ascii=False)  # not ASCII-escaped: Polish rules miss escaped text
        data = self.policy.data
        ev = AuditEvent(
            ts=datetime.now(timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z"),
            role=self.role, key_id=key_id, door="tool", verdict="allow", scan_point="tool_args",
            source=name.partition(".")[0], tool=name,
            content_sha256=hashlib.sha256(args_json.encode()).hexdigest(),
            policy_version=self.policy.version,
        )
        try:
            return await self._decide(context, call_next, name, args, args_json, auth, ident, key_id, data, ev)
        finally:
            st = taint.state(key_id)
            ev.tainted, ev.holds_private = bool(st["tainted"]), bool(st["holds_private"])
            audit.write(ev)

    async def _decide(self, context, call_next, name, args, args_json, auth, ident, key_id, data, ev):
        def deny(rule: str, msg: str):
            ev.verdict = "block"
            ev.reasons.append(Reason(rule=rule, tier=0, detail=msg))
            raise ToolError(f"{rule}: {msg}")

        t0 = time.perf_counter()
        if auth and (not ident or ident[0] != self.role):
            deny("role.denied", f"key not bound to {self.role}")
        rp = self.role_policy()
        tool = await self.server.get_tool(name)
        if tool is None or not tool_allowed(rp, tool):
            deny("role.denied", f"{name} is not available to {self.role}")
        why = check_args((rp.get("constrain") or {}).get(name, {}), args)
        ev.latency_ms["role"] = round((time.perf_counter() - t0) * 1000, 3)
        if why:
            deny("role.constraint", f"{name} {why}")

        sig = f"{name} {json.dumps(args, sort_keys=True, default=str)}"
        prev, n = self.last.get(key_id, (None, 0))
        n = n + 1 if prev == sig else 1
        self.last[key_id] = (sig, n)
        cap = (data.get("loops") or {}).get("max_identical_calls", 5)
        if n > cap:
            deny("loop.cutoff", f"{name} called {n} times in a row with identical arguments (max {cap})")

        t0 = time.perf_counter()
        blocked = taint.check(data, key_id, name)
        ev.latency_ms["taint"] = round((time.perf_counter() - t0) * 1000, 3)
        if blocked:
            deny("taint.flow", blocked)

        cpol = content_policy(data, rp)
        v = scan(args_json, "tool_args", cpol)
        apply_verdict(ev, v, "tool_args")
        if v.action == "redact":
            try:
                context.message.arguments = json.loads(v.redacted_text)
            except (TypeError, ValueError):
                deny("content.redact_failed", "redacted arguments are not valid JSON")

        result = await call_next(context)
        text = "".join(getattr(b, "text", "") for b in result.content)
        v = scan(text, "tool_result", cpol)
        apply_verdict(ev, v, "tool_result")
        if v.action == "redact":
            sc = result.structured_content
            # ponytail: only the {"result": ...} wrapper is rewritten; other structured output is dropped
            new_sc = None
            if sc and set(sc) == {"result"}:
                new_sc = {"result": v.redacted_text}
                if not isinstance(sc["result"], str):  # JSON result (e.g. rows): keep its type for the output schema
                    try:  # masks sit inside JSON strings, so the redacted text stays valid JSON
                        new_sc = {"result": json.loads(v.redacted_text)}
                    except ValueError:  # fail closed: the client rejects a result that breaks the output schema
                        deny("content.redact_failed", "redacted result is not valid JSON")
            result = ToolResult(content=[TextContent(type="text", text=v.redacted_text)],
                                structured_content=new_sc,
                                meta=result.meta, is_error=result.is_error)
        elif ev.verdict == "allow":
            ev.scan_point = "tool_result"
        taint.record(data, key_id, name, args)
        return result


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


def build_app(policy: PolicyHolder, upstream=None) -> Starlette:
    """/mcp/{role}/ per role in the policy. ponytail: roles fixed at startup; new roles need a restart."""
    sources = load_sources(policy)
    apps = {r: build_role_server(r, policy, sources).http_app(path="/") for r in policy.data["roles"]}

    @contextlib.asynccontextmanager
    async def lifespan(_):
        async with contextlib.AsyncExitStack() as stack:
            for a in apps.values():
                await stack.enter_async_context(a.router.lifespan_context(a))
            yield

    async def healthz(_):
        st = policy.status()
        return JSONResponse({"ok": True, "policy": st, "roles": list(apps), "sources": list(sources),
                             "policy_roles": list(policy.data.get("roles") or {})})

    async def admin_taint(_):  # read-only; ponytail: no auth, bind to 127.0.0.1 only
        return JSONResponse(taint.STATE)

    async def admin_budget(_):  # read-only, same caveat as /admin/taint
        return JSONResponse(model_door.budget(policy.data))

    routes = [Route("/healthz", healthz), Route("/admin/taint", admin_taint), Route("/admin/budget", admin_budget),
              Route("/v1/chat/completions", model_door.build_door(policy, upstream), methods=["POST"])]
    routes += [Mount(f"/mcp/{r}", app=require_key(r, a)) for r, a in apps.items()]
    return Starlette(routes=routes, lifespan=lifespan)
