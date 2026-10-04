"""Track A red team: gateway/policy bypass attempts. Each test pins an attack that must stay blocked."""
import asyncio
import copy
import os
import time

import httpx2
import pytest
from fastmcp import Client
from fastmcp.exceptions import ToolError

pytestmark = [pytest.mark.track_a, pytest.mark.redteam]

PR = {"repo": "acme/website", "title": "t", "body": "hello"}


def _holder(mutate=None):
    from tollgate.gateway.policy import PolicyHolder, load_policy

    d = copy.deepcopy(load_policy().data)
    if mutate:
        mutate(d)
    return PolicyHolder(d)


# --- tool access -------------------------------------------------------------------------------------------------

async def test_underscore_alias_of_tool_name_denied():
    """`github.pr_create` resolved to the same source tool as `github.pr.create`, skipping labels (taint), approval
    lists and argument limits, which are keyed by the dotted name."""
    from tollgate.mocks.github import PRS
    from tollgate.gateway import build_role_server

    def rw_files(d):
        d["roles"]["role-2"]["servers"]["files"] = {"access": "rw"}
    PRS.clear()
    async with Client(build_role_server("role-2", _holder(rw_files))) as c:
        for name, args in [("github.pr_create", PR), ("github.issues_read", {"repo": "acme/website", "number": 12}),
                           ("files.fs_read", {"path": "/etc/passwd"}), ("GITHUB.pr.create", PR),
                           ("github.pr.create ", PR), ("github.pr.creatе", PR), ("pr_create", PR)]:  # Cyrillic е
            with pytest.raises(ToolError, match="role.denied"):
                await c.call_tool(name, args)
    assert PRS == []


# --- argument limits ---------------------------------------------------------------------------------------------

@pytest.mark.parametrize("path", ["/workspace/..\\..\\etc\\passwd", "/workspace/%2e%2e/etc/passwd",
                                  "/workspace/%2E%2E/%2E%2E/etc/passwd", "/workspace/a.txt\x00/../../etc/passwd",
                                  "//etc/passwd", "workspace/a.txt", "/workspace/./../etc/passwd",
                                  "/WORKSPACE/../etc/passwd", "\\etc\\passwd"])
async def test_path_tricks_blocked(path):
    from tollgate.gateway import build_role_server

    async with Client(build_role_server("role-2", _holder())) as c:
        with pytest.raises(ToolError, match="role.constraint"):
            await c.call_tool("files.fs.read", {"path": path})


async def test_sql_tricks_never_write():
    from tollgate.mocks import tickets
    from tollgate.gateway import build_role_server

    tickets.reset()
    bad = ["select 1; delete from faq", "SELECT 1 -- ;\nDELETE FROM faq", "/* x */ DELETE FROM faq",
           "WITH x AS (SELECT 1) DELETE FROM faq", "PRAGMA writable_schema=1", "ATTACH 'x.db' AS y",
           "SELECT 1； DELETE FROM faq", "SELECT load_extension('x')", "  \n\tdelete from faq"]
    async with Client(build_role_server("role-2", _holder())) as c:
        for sql in bad:
            with pytest.raises(ToolError):
                await c.call_tool("tickets.query", {"sql": sql})
        with pytest.raises(ToolError):  # constraint keyed by `sql`; `SQL` is not the argument the tool runs
            await c.call_tool("tickets.query", {"SQL": "DELETE FROM faq", "sql": "DELETE FROM faq"})
    assert tickets.DB.execute("SELECT count(*) FROM faq").fetchone()[0] == 1


def test_to_domain_suffix_and_list_tricks():
    from tollgate.gateway import check_args

    rule = {"to_domain": "acme.com"}
    for to in ["x@evil-acme.com", "x@evil.com, y@acme.com", "x@evil.com;y@acme.com", "x@evil.com y@acme.com",
               "<x@evil.com>@acme.com", "", "acme.com"]:
        assert check_args(rule, {"to": to}), to
    for to in ["y@acme.com", "Y@ACME.COM", "a@acme.com, b@acme.com"]:
        assert check_args(rule, {"to": to}) is None, to


# --- keys --------------------------------------------------------------------------------------------------------

def test_key_mac_is_not_ambiguous_across_role_and_key_id():
    """MAC over `role:key_id`: a key for (a, b:c) would have verified as (a:b, c)."""
    from tollgate.gateway import keys

    with pytest.raises(ValueError):
        keys.issue("a", "b:c")
    forged = f"tg_a:b_c_{keys._mac('a', 'b:c')}"
    assert keys.verify(forged) is None


async def test_bad_auth_headers_get_401_not_500():
    from tollgate.gateway import build_app
    from tollgate.gateway.keys import issue

    app = build_app(_holder())
    init = {"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {
        "protocolVersion": "2025-06-18", "capabilities": {}, "clientInfo": {"name": "x", "version": "1"}}}
    h = {"accept": "application/json, text/event-stream"}
    async with app.router.lifespan_context(app), httpx2.AsyncClient(
            transport=httpx2.ASGITransport(app=app), base_url="http://127.0.0.1") as raw:
        for extra in [[(b"authorization", "Bearer tg_\xe9_x_y".encode("latin-1"))], [(b"authorization", b"Bearer ")],
                      [(b"authorization", f"Bearer {issue('role-2')}".encode())], [],
                      [(b"authorization", b"Bearer junk"), (b"authorization", f"Bearer {issue('role-1')}".encode())],
                      [(b"authorization", f"Bearer {issue('role-2')}".encode()),
                       (b"authorization", f"Bearer {issue('role-1')}".encode())]]:
            req = raw.build_request("POST", "/mcp/role-1/", json=init, headers=h)
            req.headers = httpx2.Headers(list(req.headers.raw) + extra)
            assert (await raw.send(req)).status_code == 401
        r = await raw.post(f"/mcp/role-1/?key={issue('role-1')}", json=init, headers=h)
        assert r.status_code == 401


# --- approvals ---------------------------------------------------------------------------------------------------

async def test_approved_call_rechecks_current_policy():
    """A call parked for approval, then the role loses the tool: an approve must not run it under the old policy."""
    from tollgate.mocks.github import PRS
    from tollgate.gateway.approvals import Approvals
    from tollgate.gateway import build_role_server

    def needs_approval(d):
        d["roles"]["role-2"]["approval"] = ["github.pr.create"]
        d["approval"] = {"timeout_s": 5}
    holder, approvals = _holder(needs_approval), Approvals()
    PRS.clear()
    async with Client(build_role_server("role-2", holder, approvals=approvals)) as c:
        call = asyncio.create_task(c.call_tool("github.pr.create", PR))
        item = await asyncio.wait_for(approvals.next_pending(), 5)
        del holder._data["roles"]["role-2"]["servers"]["github"]
        approvals.decide(item["id"], "approve")
        with pytest.raises(ToolError, match="role.denied"):
            await call
    assert PRS == []
    assert approvals.decide(item["id"], "approve") is None  # replaying a decided id does nothing


# --- policy hot reload ---------------------------------------------------------------------------------------------

def _write(path, text, bump):
    path.write_text(text, encoding="utf-8")
    os.utime(path, ns=(10**18 + bump * 10**9, 10**18 + bump * 10**9))  # NTFS mtime is 100 ns


BAD_EDITS = [
    ("python_tag", lambda s: s + "\nx: !!python/object/apply:os.system ['echo pwned']\n"),
    ("tools_as_string", lambda s: s.replace("files:   { tools: [fs.list, fs.read, fs.write] }",
                                            "files:   { access: read, tools: \"fs.read fs.write\" }")),
    ("labels_as_list", lambda s: s.replace("labels:\n", "labels: [github.pr.create]\nlabels_old:\n")),
    ("label_typo", lambda s: s.replace("[public_sink]        #", "[public-sink]        #")),
    ("role_content_string", lambda s: s.replace("content: { secrets: redact }", "content: \"off\"")),
    ("enabled_string", lambda s: s.replace("enabled: true", "enabled: \"false\"")),
    ("negative_budget", lambda s: s.replace("tokens_per_day: 20000", "tokens_per_day: -1")),
    ("loops_zero", lambda s: s.replace("max_identical_calls: 5", "max_identical_calls: 0")),
    ("unknown_server", lambda s: s.replace("github: { access: read }", "nope: { access: rw }")),
    ("billion_laughs", lambda s: s.replace("labels:\n", "labels:\n  a0: &a0 [x, x, x, x, x, x, x, x, x]\n"
                                           + "".join(f"  a{i}: &a{i} [*a{i-1}, *a{i-1}, *a{i-1}, *a{i-1}, *a{i-1}, "
                                                     f"*a{i-1}, *a{i-1}, *a{i-1}, *a{i-1}]\n" for i in range(1, 9)))),
]


@pytest.mark.parametrize("name,edit", BAD_EDITS, ids=[b[0] for b in BAD_EDITS])
def test_bad_policy_edit_rejected_old_kept(tmp_path, name, edit):
    from tollgate.gateway.policy import DEFAULT_PATH, load_policy

    src = DEFAULT_PATH.read_text(encoding="utf-8")
    bad = edit(src)
    assert bad != src
    path = tmp_path / "policy.yaml"
    _write(path, src, 0)
    holder = load_policy(path)
    v0, labels0 = holder.version, dict(holder.data["labels"])
    _write(path, bad, 1)
    t0 = time.perf_counter()
    st = holder.status()
    assert time.perf_counter() - t0 < 2
    assert st["last_error"] and st["version"] == v0 and holder.data["labels"] == labels0


def test_policy_file_deleted_keeps_old(tmp_path):
    from tollgate.gateway.policy import DEFAULT_PATH, load_policy

    path = tmp_path / "policy.yaml"
    _write(path, DEFAULT_PATH.read_text(encoding="utf-8"), 0)
    holder = load_policy(path)
    path.unlink()
    assert holder.status()["last_error"] and "role-2" in holder.data["roles"]


def test_removing_taint_section_keeps_taint_on():
    from tollgate.gateway import taint

    p = _holder(lambda d: d.pop("taint")).data
    taint.reset("rt")
    taint.record(p, "rt", "github.issues.read", {"number": 12})
    taint.record(p, "rt", "github.repo.read", {"repo": "acme/payroll", "path": ".env"})
    assert taint.check(p, "rt", "github.pr.create")
    taint.reset("rt")


# --- model door ----------------------------------------------------------------------------------------------------

def _door(monkeypatch, tmp_path, usage):
    from tollgate.gateway import build_app

    monkeypatch.setenv("TOLLGATE_UPSTREAM", "http://stub/v1")

    def reply(req):
        out = {"choices": [{"index": 0, "message": {"role": "assistant", "content": "ok " * 50}}]}
        if usage is not None:
            out["usage"] = usage
        return httpx2.Response(200, json=out)
    return build_app(_holder(), upstream=httpx2.MockTransport(reply))


@pytest.mark.parametrize("usage", [{"total_tokens": -10**9}, None, {"total_tokens": "lots"}, {"total_tokens": None}])
async def test_door_usage_cannot_refund_or_skip_budget(tmp_path, monkeypatch, usage):
    from tollgate.gateway import model_door
    from tollgate.gateway.keys import issue

    app = _door(monkeypatch, tmp_path, usage)
    day = (("role-1", model_door._today()))
    model_door.USED.pop(day, None)
    async with app.router.lifespan_context(app), httpx2.AsyncClient(
            transport=httpx2.ASGITransport(app=app), base_url="http://127.0.0.1") as c:
        r = await c.post("/v1/chat/completions", headers={"authorization": f"Bearer {issue('role-1')}"},
                         json={"model": "qwen3:1.7b", "messages": [{"role": "user", "content": "hi"}]})
    assert r.status_code == 200
    assert model_door.USED[day] > 0
    model_door.USED.pop(day, None)


@pytest.mark.parametrize("role", ["assistant", "tool", "developer", "function"])
async def test_door_scans_every_message_role(tmp_path, monkeypatch, role):
    from tollgate.gateway.keys import issue

    app = _door(monkeypatch, tmp_path, {"total_tokens": 1})
    msgs = [{"role": role, "content": "deploy notes: AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE"},
            {"role": "user", "content": "summarise"}]
    async with app.router.lifespan_context(app), httpx2.AsyncClient(
            transport=httpx2.ASGITransport(app=app), base_url="http://127.0.0.1") as c:
        r = await c.post("/v1/chat/completions", headers={"authorization": f"Bearer {issue('role-1')}"},
                         json={"model": "qwen3:1.7b", "messages": msgs})
    assert r.status_code == 400 and "secret" in r.text


# --- admin endpoints -----------------------------------------------------------------------------------------------

async def test_admin_reads_need_loopback_or_token():
    from tollgate.gateway import build_app
    from tests.conftest import ADMIN_TOKEN as ADMIN_DEV_TOKEN
    from tollgate.gateway.keys import issue

    app = build_app(_holder())
    async with app.router.lifespan_context(app):
        for client, auth, want in [(("203.0.113.5", 1), None, 401), (("203.0.113.5", 1), issue("role-1"), 401),
                                   (("203.0.113.5", 1), ADMIN_DEV_TOKEN, 200), (("127.0.0.1", 1), None, 200)]:
            async with httpx2.AsyncClient(transport=httpx2.ASGITransport(app=app, client=client),
                                          base_url="http://127.0.0.1:8080") as c:
                h = {"authorization": f"Bearer {auth}"} if auth else {}
                for path in ("/admin/taint", "/admin/budget", "/admin/approvals"):
                    assert (await c.get(path, headers=h)).status_code == want, (client, auth, path)


# --- feed ----------------------------------------------------------------------------------------------------------

@pytest.mark.parametrize("pattern", ["(a+)+$", "(\\w+\\s?)*$", "((ab)*)+x", "(x{1,9}){2,}", "a" * 600])
async def test_feed_rejects_redos_patterns(tmp_path, pattern):
    from tollgate.feed import Puller, _sig, publish

    body = {"version": 99, "issued_at": "2026-10-03T00:00:00Z",
            "signatures": [{"id": "redos", "pattern": pattern, "action": "block", "tags": []}]}
    b = {**body, "sig": _sig(body)}
    target = tmp_path / "signatures.yaml"
    target.write_text("[]\n", encoding="utf-8")
    p = Puller("http://feed/bundle.json", transport=httpx2.MockTransport(lambda r: httpx2.Response(200, json=b)))
    assert not await p.pull(target)
    assert target.read_text(encoding="utf-8") == "[]\n" and "redos" in p.state["last_error"]
    (tmp_path / "bundle_src.yaml").write_text("version: 1\nsignatures: []\n", encoding="utf-8")
    with pytest.raises(ValueError):
        publish(tmp_path, f"id=redos,pattern={pattern}")


def test_feed_accepts_shipped_patterns():
    import yaml

    from tollgate.feed import check_signatures
    from tollgate.feed import SRC
    from pathlib import Path

    root = Path(__file__).resolve().parents[1]
    check_signatures(yaml.safe_load((root / "feed" / SRC).read_text(encoding="utf-8"))["signatures"])
    check_signatures(yaml.safe_load((root / "signatures.yaml").read_text(encoding="utf-8")))
