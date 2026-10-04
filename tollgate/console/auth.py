"""Console sign-in (docs/ui-spec.md "Server console, accounts"): who is calling /console/api/*, and may they do this.

Every request: the Host must name this server (loopback names or TOLLGATE_ALLOWED_HOSTS: anti DNS rebinding). Identity:
a session cookie (tg_session) or `Authorization: Bearer $TOLLGATE_ADMIN_TOKEN` (only when that env var is set; there is
no default token). Writes: role admin, the session's CSRF token in X-CSRF-Token, a same-origin Origin, and
Content-Type: application/json. Before any account exists loopback may read (first run), never write; the browser
shows "Create the owner account", which only loopback may submit.
ponytail: behind a reverse proxy every client looks loopback and the scheme reads http; set the account up first."""
import hmac

from starlette.requests import Request
from starlette.responses import JSONResponse
from starlette.routing import Route

from tollgate import accounts
from tollgate.gateway.approvals import admin_ok, host_ok, loopback

SAFE = ("GET", "HEAD", "OPTIONS")
VIEWER_POST = {"/console/api/try"}  # a dry-run content check: changes nothing, so viewers may run it
NO_STORE = {"Cache-Control": "no-store"}
TOKEN_WHO = {"email": "admin-token", "name": "Admin token", "role": "admin", "csrf": None, "via": "token"}


def json_post(request: Request) -> bool:
    """POSTs must say application/json: a form or text/plain POST from another site is a "simple" request that skips
    the CORS preflight."""
    return request.headers.get("content-type", "").split(";")[0].strip().lower() == "application/json"


def refuse(request: Request) -> JSONResponse | None:
    """The checks every /console/api request passes before identity: Host, and for writes Origin + JSON."""
    if not host_ok(request):
        return err("Unknown host. Add it to TOLLGATE_ALLOWED_HOSTS to serve the console under that name.", 403)
    if request.method not in SAFE:
        if not same_origin(request):
            return err("Cross-site request refused.", 403)
        if not json_post(request):
            return err("Send Content-Type: application/json.", 415)
    return None


def same_origin(request: Request) -> bool:
    """Browsers send Origin on every cross-origin POST; a mismatch is a request some other site made."""
    o = request.headers.get("origin")
    if o is not None:
        return o == f"{request.url.scheme}://{request.headers.get('host', '')}"
    return request.headers.get("sec-fetch-site", "same-origin") in ("same-origin", "none")


def who(request: Request) -> dict | None:
    """The admin token (only when TOLLGATE_ADMIN_TOKEN is set), a session, or, before any account exists, loopback for
    reads only (gate refuses its writes)."""
    if admin_ok(request.headers.get("authorization")):
        return TOKEN_WHO
    if not accounts.any_users():
        return {"email": "loopback", "name": "Local", "role": "admin", "csrf": None, "via": "loopback"}             if loopback(request) else None
    s = accounts.session(request.cookies.get(accounts.COOKIE))
    return {**s, "via": "session"} if s else None


def err(msg: str, code: int, **kw) -> JSONResponse:
    return JSONResponse({"error": msg, **kw}, code, headers=NO_STORE)


def gate(view, admin_only: bool = False):
    """Wraps every /console/api/* view: signed in, and for writes admin + CSRF + same origin."""
    async def h(request: Request):
        if bad := refuse(request):
            return bad
        w = who(request)
        if not w:
            return err("Sign in to the console.", 401, login=True)
        write = request.method not in SAFE
        if write and w["via"] == "loopback":  # no account yet: a local process must not change policy unauthenticated
            return err("Create the owner account first (or send the admin token).", 401, setup=True)
        if (admin_only or (write and request.url.path not in VIEWER_POST)) and w["role"] != "admin":
            return err("Viewers can look but not change anything. Ask an admin.", 403)
        if write and w["via"] == "session" and not hmac.compare_digest(
                request.headers.get("x-csrf-token", "").encode(), w["csrf"].encode()):
            return err("Missing or stale security token. Reload the page and try again.", 403)
        request.state.who = w["email"]
        return await view(request)
    return h


def _cookie(resp: JSONResponse, request: Request, sid: str) -> JSONResponse:
    resp.set_cookie(accounts.COOKIE, sid, max_age=int(accounts.SESSION_TTL.total_seconds()), path="/console",
                    httponly=True, samesite="strict", secure=request.url.scheme == "https")
    return resp


def _signed_in(request: Request, sid: str, user: dict) -> JSONResponse:
    s = accounts.session(sid)
    return _cookie(JSONResponse({**user, "csrf": s["csrf"]}, headers=NO_STORE), request, sid)


async def _body(request: Request) -> dict:
    try:
        b = await request.json()
    except ValueError:
        return {}
    return b if isinstance(b, dict) else {}


def routes() -> list:
    async def me(request):
        if bad := refuse(request):
            return bad
        w, setup = who(request), not accounts.any_users()
        if setup:
            return JSONResponse({"setup": True, "can_setup": loopback(request)}, 200 if w else 401, headers=NO_STORE)
        if not w:
            return err("Sign in to the console.", 401, setup=False)
        return JSONResponse({k: w[k] for k in ("email", "name", "role", "csrf", "via")}, headers=NO_STORE)

    async def setup(request):
        if bad := refuse(request):
            return bad
        if not loopback(request):
            return err("The owner account can only be created on the server itself (or with `tollgate admin create`).", 403)
        b = await _body(request)
        try:
            u = accounts.create_user(b.get("email"), b.get("password"), "admin", b.get("name"), only_if_empty=True)
        except ValueError as e:
            return err(str(e), 400)
        accounts.log(u["email"], "Created the owner account")
        sid, u = accounts.new_session(u["email"])
        return _signed_in(request, sid, u)

    async def login(request):
        if bad := refuse(request):
            return bad
        b = await _body(request)
        try:
            sid, u = accounts.login(b.get("email"), b.get("password"), request.client.host if request.client else "",
                                    request.cookies.get(accounts.COOKIE))
        except accounts.RateLimited:
            return JSONResponse({"error": "Too many failed attempts. Wait 5 minutes and try again."}, 429,
                                headers={**NO_STORE, "Retry-After": str(accounts.FAIL_WINDOW_S)})
        except ValueError as e:
            return err(str(e), 401)
        return _signed_in(request, sid, u)

    async def logout(request):
        if bad := refuse(request):
            return bad
        accounts.logout(request.cookies.get(accounts.COOKIE))
        resp = JSONResponse({"ok": True}, headers=NO_STORE)
        resp.delete_cookie(accounts.COOKIE, path="/console")
        return resp

    async def accept(request):
        if bad := refuse(request):
            return bad
        b = await _body(request)
        try:
            u = accounts.accept(b.get("token"), b.get("name"), b.get("password"))
        except ValueError as e:
            return err(str(e), 400)
        sid, u = accounts.new_session(u["email"], request.cookies.get(accounts.COOKIE))
        return _signed_in(request, sid, u)

    async def users(request):
        return JSONResponse({"users": accounts.listing(), "log": accounts.recent_log(50), "me": request.state.who},
                            headers=NO_STORE)

    async def invite(request):
        b = await _body(request)
        try:
            t = accounts.invite(b.get("email"), b.get("role"), request.state.who)
        except ValueError as e:
            return err(str(e), 400)
        link = f"{request.url.scheme}://{request.headers.get('host', '')}/console/#/accept/{t['token']}"
        return JSONResponse({"link": link, "email": t["email"], "role": t["role"], "expires_at": t["expires_at"]},
                            headers=NO_STORE)

    async def set_role(request):
        b = await _body(request)
        try:
            return JSONResponse(accounts.set_role(request.path_params["email"], b.get("role"), request.state.who))
        except KeyError:
            return err("unknown user", 404)
        except ValueError as e:
            return err(str(e), 400)

    async def set_disabled(request):
        b = await _body(request)
        if not isinstance(b.get("disabled"), bool):
            return err("need {disabled: true|false}", 400)
        try:
            return JSONResponse(accounts.set_disabled(request.path_params["email"], b["disabled"], request.state.who))
        except KeyError:
            return err("unknown user", 404)
        except ValueError as e:
            return err(str(e), 400)

    return [Route("/auth/me", me), Route("/auth/setup", setup, methods=["POST"]),
            Route("/auth/login", login, methods=["POST"]), Route("/auth/logout", logout, methods=["POST"]),
            Route("/auth/accept", accept, methods=["POST"]),
            Route("/users", gate(users, admin_only=True)),
            Route("/users/invite", gate(invite, admin_only=True), methods=["POST"]),
            Route("/users/{email}/role", gate(set_role, admin_only=True), methods=["POST"]),
            Route("/users/{email}/disabled", gate(set_disabled, admin_only=True), methods=["POST"])]
