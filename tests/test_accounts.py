"""Console accounts: owner setup, login, sessions, roles (admin|viewer), CSRF + same-origin on writes, invites,
attribution. tests/conftest.py points TOLLGATE_ACCOUNTS at a tmp file."""
import contextlib
import json

import httpx2
import pytest

from tests.conftest import ADMIN
from tollgate import accounts

pytestmark = pytest.mark.track_a
BASE = "http://127.0.0.1:8080"
PW = "correct horse battery"
ORIGIN = {"Origin": BASE}


@pytest.fixture(autouse=True)
def _no_failures():
    accounts._FAILS.clear()
    yield
    accounts._FAILS.clear()


@contextlib.asynccontextmanager
async def _app(monkeypatch, tmp_path, client=("127.0.0.1", 123), base=BASE):
    monkeypatch.setenv("TOLLGATE_UPSTREAM", "scripted")
    from tollgate.gateway import build_app
    from tollgate.gateway.policy import DEFAULT_PATH, load_policy
    path = tmp_path / "policy.yaml"
    path.write_bytes(DEFAULT_PATH.read_bytes())
    holder = load_policy(path)
    app = build_app(holder)
    async with app.router.lifespan_context(app):
        async with httpx2.AsyncClient(transport=httpx2.ASGITransport(app=app, client=client), base_url=base) as c:
            yield c, app, holder


def _client(app, client=("127.0.0.1", 124)):
    return httpx2.AsyncClient(transport=httpx2.ASGITransport(app=app, client=client), base_url=BASE)


async def _signin(c, email, pw=PW) -> dict:
    r = await c.post("/console/api/auth/login", json={"email": email, "password": pw}, headers=ORIGIN)
    assert r.status_code == 200, r.text
    return {**ORIGIN, "X-CSRF-Token": r.json()["csrf"]}


def _write_routes(app) -> list[str]:
    """Every POST under /console/api except sign-in itself, path params filled in."""
    from starlette.routing import Mount
    api = next(r for r in app.routes if isinstance(r, Mount) and r.path == "/console/api")
    out = []
    for r in api.routes:
        if "POST" in (r.methods or ()) and not r.path.startswith("/auth/"):
            out.append("/console/api" + r.path.replace("{id}", "pzzzz").replace("{email}", "x@y.io"))
    return out


async def test_zero_accounts_mode_unchanged(monkeypatch, tmp_path):
    async with _app(monkeypatch, tmp_path) as (c, app, _):
        assert (await c.get("/console/api/status")).status_code == 200  # loopback reads, no login (first run)
        r = await c.post("/console/api/enroll-token", json={})  # but a local process may not write unauthenticated
        assert r.status_code == 401 and r.json()["setup"] is True
        r = await c.post("/console/api/policy/profile", json={"profile": "lenient"})
        assert r.status_code == 401
        assert (await c.post("/console/api/enroll-token", json={}, headers=ADMIN)).status_code == 200
        me = (await c.get("/console/api/auth/me")).json()
        assert me == {"setup": True, "can_setup": True}
        async with _client(app, ("10.0.0.9", 1)) as remote:
            assert (await remote.get("/console/api/status")).status_code == 401
            r = await remote.get("/console/api/auth/me")
            assert r.status_code == 401 and r.json()["can_setup"] is False
        # a browser on another site: cross-origin, simple (text/plain) POST, DNS rebinding
        evil = {**ADMIN, "Origin": "https://evil.example", "Content-Type": "text/plain"}
        assert (await c.post("/console/api/policy/profile", content='{"profile":"lenient"}', headers=evil)).status_code == 403
        plain = {**ADMIN, "Content-Type": "text/plain"}
        assert (await c.post("/console/api/policy/profile", content='{"profile":"lenient"}', headers=plain)).status_code == 415
        assert (await c.get("/console/api/status", headers={"Host": "evil.example"})).status_code == 403
        assert (await c.get("/healthz", headers={"Host": "evil.example"})).json() == {"ok": True}
        monkeypatch.setenv("TOLLGATE_ALLOWED_HOSTS", "hub.acme.io")
        assert (await c.get("/console/api/status", headers={"Host": "hub.acme.io:8080"})).status_code == 200


async def test_setup_only_from_loopback_and_once(monkeypatch, tmp_path):
    async with _app(monkeypatch, tmp_path) as (c, app, _):
        body = {"email": "Ola@Acme.io", "name": "Ola", "password": PW}
        async with _client(app, ("10.0.0.9", 1)) as remote:
            assert (await remote.post("/console/api/auth/setup", json=body, headers=ORIGIN)).status_code == 403
        assert not accounts.any_users()
        r = await c.post("/console/api/auth/setup", json={**body, "password": "short"}, headers=ORIGIN)
        assert r.status_code == 400 and "12" in r.json()["error"]
        r = await c.post("/console/api/auth/setup", json=body, headers=ORIGIN)
        assert r.status_code == 200 and r.json()["role"] == "admin" and r.json()["email"] == "ola@acme.io"
        assert (await c.get("/console/api/auth/me")).json()["email"] == "ola@acme.io"
        assert (await c.post("/console/api/auth/setup", json={**body, "email": "x@y.io"}, headers=ORIGIN)).status_code == 400
        async with _client(app) as other:  # loopback no longer bypasses login
            assert (await other.get("/console/api/status")).status_code == 401
            assert (await other.get("/admin/taint")).status_code == 401
        store = accounts.path().read_text()
        assert PW not in store and "scrypt$" in store


async def test_cookie_flags(monkeypatch, tmp_path):
    accounts.create_user("ola@acme.io", PW)
    monkeypatch.setenv("TOLLGATE_ALLOWED_HOSTS", "hub.acme.io")
    for base, secure in ((BASE, False), ("https://hub.acme.io", True)):
        async with _app(monkeypatch, tmp_path, base=base) as (c, _, _h):
            r = await c.post("/console/api/auth/login", json={"email": "ola@acme.io", "password": PW},
                             headers={"Origin": base})
            sc = r.headers["set-cookie"].lower()
            assert r.status_code == 200 and sc.startswith("tg_session=")
            assert "httponly" in sc and "samesite=strict" in sc and "path=/console" in sc and "max-age=43200" in sc
            assert ("secure" in sc) is secure


async def test_login_logout_me_and_rotation(monkeypatch, tmp_path):
    accounts.create_user("ola@acme.io", PW, name="Ola")
    async with _app(monkeypatch, tmp_path) as (c, _, _h):
        assert (await c.get("/console/api/auth/me")).status_code == 401
        await _signin(c, "OLA@acme.io")
        old = c.cookies.get("tg_session")
        me = (await c.get("/console/api/auth/me")).json()
        assert me["email"] == "ola@acme.io" and me["name"] == "Ola" and me["role"] == "admin" and len(me["csrf"]) > 30
        await _signin(c, "ola@acme.io")  # login again: the old id is gone
        assert c.cookies.get("tg_session") != old and accounts.session(old) is None
        assert (await c.post("/console/api/auth/logout", json={}, headers=ORIGIN)).status_code == 200
        assert (await c.get("/console/api/auth/me")).status_code == 401
        assert (await c.get("/console/api/overview")).status_code == 401


async def test_wrong_password_generic_and_rate_limit(monkeypatch, tmp_path):
    accounts.create_user("ola@acme.io", PW)
    async with _app(monkeypatch, tmp_path) as (c, _, _h):
        a = await c.post("/console/api/auth/login", json={"email": "ola@acme.io", "password": "nope nope nope"}, headers=ORIGIN)
        b = await c.post("/console/api/auth/login", json={"email": "who@acme.io", "password": "nope nope nope"}, headers=ORIGIN)
        assert a.status_code == b.status_code == 401 and a.json() == b.json() == {"error": "Wrong email or password"}
        for _ in range(4):
            await c.post("/console/api/auth/login", json={"email": "ola@acme.io", "password": "x"}, headers=ORIGIN)
        r = await c.post("/console/api/auth/login", json={"email": "ola@acme.io", "password": PW}, headers=ORIGIN)
        assert r.status_code == 429 and "set-cookie" not in r.headers
        r = await c.post("/console/api/auth/login", json={"email": "ola@acme.io", "password": PW},
                         headers=ORIGIN)
        assert r.status_code == 429


async def test_viewer_gets_403_on_every_write_route(monkeypatch, tmp_path):
    accounts.create_user("ola@acme.io", PW)
    accounts.create_user("vic@acme.io", PW, role="viewer")
    async with _app(monkeypatch, tmp_path) as (c, app, _):
        h = await _signin(c, "vic@acme.io")
        writes = _write_routes(app)
        assert {"/console/api/policy/access", "/console/api/peers/pzzzz/revoke", "/console/api/enroll-token",
                "/console/api/feed/publish", "/console/api/selftest/run", "/console/api/users/invite"} <= set(writes)
        for path in writes:
            r = await c.post(path, json={}, headers=h)
            if path == "/console/api/try":  # dry run: viewers may use it (bad body -> 400, not 403)
                assert r.status_code == 400, path
                continue
            assert r.status_code == 403 and "Viewers" in r.json()["error"], path
        assert (await c.get("/console/api/users")).status_code == 403
        for path in ("/console/api/overview", "/console/api/peers", "/console/api/policy", "/console/api/feed"):
            assert (await c.get(path)).status_code == 200, path


async def test_csrf_and_origin_required_on_writes(monkeypatch, tmp_path):
    accounts.create_user("ola@acme.io", PW)
    async with _app(monkeypatch, tmp_path) as (c, _, _h):
        h = await _signin(c, "ola@acme.io")
        p = "/console/api/enroll-token"
        assert (await c.post(p, json={}, headers=ORIGIN)).status_code == 403
        assert (await c.post(p, json={}, headers={**h, "X-CSRF-Token": "wrong"})).status_code == 403
        assert (await c.post(p, json={}, headers={**h, "Origin": "https://evil.example"})).status_code == 403
        assert (await c.post(p, json={}, headers={"X-CSRF-Token": h["X-CSRF-Token"], "Sec-Fetch-Site": "cross-site"})).status_code == 403
        assert (await c.post(p, content="{}", headers={**h, "Content-Type": "text/plain"})).status_code == 415
        assert (await c.post("/console/api/auth/login", json={"email": "ola@acme.io", "password": PW},
                             headers={"Origin": "https://evil.example"})).status_code == 403
        assert (await c.post(p, json={}, headers=h)).status_code == 200


async def test_invite_accept_once_and_expiry(monkeypatch, tmp_path):
    accounts.create_user("ola@acme.io", PW)
    async with _app(monkeypatch, tmp_path) as (c, app, _):
        h = await _signin(c, "ola@acme.io")
        r = await c.post("/console/api/users/invite", json={"email": "vic@acme.io", "role": "viewer"}, headers=h)
        assert r.status_code == 200, r.text
        link = r.json()["link"]
        token = link.split("#/accept/")[1]
        assert link.startswith(BASE + "/console/#/accept/") and token not in accounts.path().read_text()
        async with _client(app, ("10.0.0.9", 1)) as v:
            bad = await v.post("/console/api/auth/accept", json={"token": token, "password": "short"}, headers=ORIGIN)
            assert bad.status_code == 400
            ok = await v.post("/console/api/auth/accept", json={"token": token, "name": "Vic", "password": PW}, headers=ORIGIN)
            assert ok.status_code == 200 and ok.json()["role"] == "viewer"
            assert (await v.get("/console/api/auth/me")).json()["email"] == "vic@acme.io"
            again = await v.post("/console/api/auth/accept", json={"token": token, "password": PW}, headers=ORIGIN)
            assert again.status_code == 400
        t2 = accounts.invite("old@acme.io", "admin", "ola@acme.io")
        db = json.loads(accounts.path().read_text())
        for i in db["invites"].values():
            if i["email"] == "old@acme.io":
                i["expires_at"] = "2000-01-01T00:00:00Z"
        accounts.path().write_text(json.dumps(db))
        with pytest.raises(ValueError):
            accounts.accept(t2["token"], "Old", PW)
        assert (await c.post("/console/api/users/invite", json={"email": "vic@acme.io", "role": "viewer"},
                             headers=h)).status_code == 400  # already has an account


async def test_last_admin_and_self_protection(monkeypatch, tmp_path):
    accounts.create_user("ola@acme.io", PW)
    accounts.create_user("vic@acme.io", PW, role="viewer")
    async with _app(monkeypatch, tmp_path) as (c, app, _):
        h = await _signin(c, "ola@acme.io")
        u = "/console/api/users/"
        assert (await c.post(u + "ola@acme.io/role", json={"role": "viewer"}, headers=h)).status_code == 400
        assert (await c.post(u + "ola@acme.io/disabled", json={"disabled": True}, headers=h)).status_code == 400
        async with _client(app) as v:
            await _signin(v, "vic@acme.io")
            assert (await v.get("/console/api/auth/me")).json()["role"] == "viewer"
            assert (await c.post(u + "vic@acme.io/role", json={"role": "admin"}, headers=h)).status_code == 200
            assert (await v.get("/console/api/auth/me")).json()["role"] == "admin"  # applies at once
            assert (await c.post(u + "vic@acme.io/disabled", json={"disabled": True}, headers=h)).status_code == 200
            assert (await v.get("/console/api/auth/me")).status_code == 401  # signed out everywhere
            r = await v.post("/console/api/auth/login", json={"email": "vic@acme.io", "password": PW}, headers=ORIGIN)
            assert r.status_code == 401
        assert (await c.post(u + "nobody@acme.io/role", json={"role": "admin"}, headers=h)).status_code == 404
        log = (await c.get("/console/api/users")).json()["log"]
        assert log[0]["who"] == "ola@acme.io" and log[0]["what"] == "Disabled vic@acme.io"


async def test_admin_token_still_works(monkeypatch, tmp_path):
    accounts.create_user("ola@acme.io", PW)
    monkeypatch.delenv("TOLLGATE_ADMIN_TOKEN")
    async with _app(monkeypatch, tmp_path, client=("10.0.0.9", 1)) as (c, _, _h):
        dev = {"Authorization": "Bearer tollgate-admin-dev"}  # the old public default: no token path when unset
        assert (await c.get("/console/api/status", headers=dev)).status_code == 401
        assert (await c.get("/admin/taint", headers=dev)).status_code == 401
        assert (await c.get("/healthz")).json() == {"ok": True}  # details are admin-only
        monkeypatch.setenv("TOLLGATE_ADMIN_TOKEN", "s3cret-automation-token")
        tok = {"Authorization": "Bearer s3cret-automation-token"}
        assert (await c.get("/console/api/status", headers=tok)).status_code == 200
        assert (await c.post("/console/api/enroll-token", json={}, headers=tok)).status_code == 200  # no cookie: no CSRF
        assert (await c.get("/admin/taint", headers=tok)).status_code == 200
        assert accounts.recent_log(1)[0]["who"] == "admin-token"


async def test_attribution_in_history_and_admin_log(monkeypatch, tmp_path):
    accounts.create_user("ola@acme.io", PW)
    async with _app(monkeypatch, tmp_path) as (c, _, holder):
        h = await _signin(c, "ola@acme.io")
        r = await c.post("/console/api/policy/access", headers=h, json={
            "base_version": holder.version, "changes": [{"role": "role-2", "tool": "files.fs.delete", "allowed": True}]})
        assert r.status_code == 200, r.text
        hist = (await c.get("/console/api/policy")).json()["history"][0]
        assert hist["note"] == "Edited in console by ola@acme.io"
        r = await c.post("/console/api/policy/profile", json={"profile": "strict"}, headers=h)
        assert r.status_code == 200
        assert (await c.get("/console/api/policy")).json()["history"][0]["note"].endswith("by ola@acme.io")
        assert (await c.post("/console/api/enroll-token", json={}, headers=h)).status_code == 200
        log = (await c.get("/console/api/users")).json()["log"]
        whats = [x["what"] for x in log]
        assert whats[0] == "Created a one-time enroll command" and all(x["who"] == "ola@acme.io" for x in log)
        assert any(w.startswith("Edited access: Support assistant may now delete a file") for w in whats)
