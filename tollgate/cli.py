"""`tollgate` command. Subcommands land as tracks build them (up/serve/approve/deny/replay/key: A, test: B)."""
import sys


def replay(name: str) -> int:
    """Runs an attack trace (github | supabase) as role-2 with taint off, then on. In-process, no server needed."""
    import asyncio
    import copy

    from mocks import tickets
    from mocks.github import PRS
    from tollgate.gateway.policy import PolicyHolder, load_policy
    from tollgate.gateway.replay import TRACES, run_trace

    trace = TRACES[name]
    on = load_policy()
    off = copy.deepcopy(on.data)
    off.setdefault("taint", {})["enabled"] = False
    for label, policy in (("taint OFF (roles only)", PolicyHolder(off)), ("taint ON", on)):
        PRS.clear()
        tickets.reset()
        print(f"== {label} ==")
        for i, ((tool, args), s) in enumerate(zip(trace, asyncio.run(run_trace(policy, trace))), 1):
            shown = {k: v for k, v in args.items() if k not in ("body", "text")}
            print(f"  {i}. {tool} {shown} -> {s['verdict'].upper()}: {s['text'].strip().splitlines()[0][:170]}")
        if name == "github":
            print(f"  PRs created: {len(PRS)}" + (f", body leaks: {PRS[0]['body'].strip().splitlines()[-2:]}" if PRS else ""))
        else:
            r = tickets.replies()
            print(f"  ticket replies: {len(r)}" + (f", ticket #3 thread now shows: {r[3][:170]}" if 3 in r else ""))
    return 0


def _opt(name: str, default: str | None = None) -> str | None:
    args = sys.argv[2:]
    return args[args.index(name) + 1] if name in args and args.index(name) + 1 < len(args) else default


def serve() -> int:
    """One process: role MCPs (mocks in-process), model door, /healthz, /admin/taint, /admin/budget. Policy hot reloads on the next request."""
    import logging

    import uvicorn

    from tollgate.gateway import build_app
    from tollgate.gateway.policy import DEFAULT_PATH, load_policy

    logging.basicConfig(level=logging.WARNING)  # policy reloads/rejections log at WARNING/ERROR
    port = int(_opt("--port", "8080"))
    holder = load_policy(_opt("--policy") or DEFAULT_PATH)
    if "--scripted-model" in sys.argv:  # model door -> in-process scripted hijacked LLM (offline demo)
        import os
        os.environ["TOLLGATE_UPSTREAM"] = "scripted"
    app = build_app(holder)
    base = f"http://127.0.0.1:{port}"
    print(f"Tollgate on {base}  policy {holder.status()['version']} ({holder.path})")
    for role in holder.data["roles"]:
        print(f"  {role}: {base}/mcp/{role}/   (key per agent launch: tollgate connect <agent> --role {role} --peer P)")
    import os

    from tollgate.gateway.model_door import DEFAULT_UPSTREAM
    print(f"  model door: {base}/v1/chat/completions  -> {os.environ.get('TOLLGATE_UPSTREAM') or DEFAULT_UPSTREAM}")
    print(f"  health: {base}/healthz   taint: {base}/admin/taint   budget: {base}/admin/budget", flush=True)
    print(f"  approvals: {base}/admin/approvals   (tollgate approve|deny <id>)", flush=True)
    print(f"  edge UI: {base}/edge   console: {base}/console", flush=True)
    if not os.environ.get("TOLLGATE_ADMIN_TOKEN"):
        print("  WARNING: TOLLGATE_ADMIN_TOKEN is not set: the admin token is off (approve/deny and /admin/* from other "
              "hosts need it). Console: sign in with an account (`tollgate admin create`).", flush=True)
    # open /edge tabs hold an endless SSE stream; without a cap uvicorn waits on it forever at Ctrl+C
    uvicorn.run(app, host="127.0.0.1", port=port, log_level="warning", timeout_graceful_shutdown=1)
    return 0


def agent() -> int:
    """Demo agent through both doors. --scripted without --base: in-process gateway + scripted hijacked model."""
    import asyncio
    import os

    import httpx2

    from tollgate.agent import run
    from tollgate.gateway.keys import issue

    rest, i = sys.argv[2:], 0
    while i < len(rest) and rest[i].startswith("--"):
        i += 1 if rest[i] == "--scripted" else 2
    task = rest[i] if i < len(rest) else "check the open issues on acme/website and handle them"
    role, model, base = _opt("--role", "role-2"), _opt("--model", "qwen3:4b"), _opt("--base")
    key = os.environ.get("TOLLGATE_KEY") or issue(role)  # a running server takes a minted key (tollgate connect)
    print(f"[agent] role={role} model={model} task={task!r}")
    if base or "--scripted" not in sys.argv:
        asyncio.run(run(task, role, model, base or "http://127.0.0.1:8080", key))
        return 0

    from tollgate.gateway import build_app
    from tollgate.gateway.policy import DEFAULT_PATH, PolicyHolder, load_policy

    os.environ["TOLLGATE_UPSTREAM"] = "scripted"
    data = load_policy(_opt("--policy") or DEFAULT_PATH).data  # in-process: its own hand-issued key is allowed here
    app = build_app(PolicyHolder({**data, "allow_unenrolled_keys": True}))

    def factory(**kw):
        return httpx2.AsyncClient(transport=httpx2.ASGITransport(app=app), base_url="http://t", **kw)

    async def go():
        async with app.router.lifespan_context(app):
            await run(task, role, model, "http://t", key, factory=factory)
    asyncio.run(go())
    return 0


def decide(id: str, decision: str) -> int:
    """POST /admin/approvals/{id} with the admin token (env TOLLGATE_ADMIN_TOKEN; there is no default)."""
    import json
    import os
    import urllib.error
    import urllib.request

    if not os.environ.get("TOLLGATE_ADMIN_TOKEN"):
        print("Set TOLLGATE_ADMIN_TOKEN (the same value the server runs with).", file=sys.stderr)
        return 2
    req = urllib.request.Request(
        f"http://127.0.0.1:{_opt('--port', '8080')}/admin/approvals/{id}", method="POST",
        data=json.dumps({"decision": decision}).encode(),
        headers={"Content-Type": "application/json",
                 "Authorization": f"Bearer {os.environ['TOLLGATE_ADMIN_TOKEN']}"})
    try:
        with urllib.request.urlopen(req, timeout=10) as r:
            print(r.read().decode())
            return 0
    except urllib.error.HTTPError as e:
        print(f"{e.code}: {e.read().decode()}", file=sys.stderr)
        return 1


def feed(sub: str) -> int:
    """P6 signature feed: serve (the external system), publish --add 'id=..,pattern=..,action=..,tags=A;B', pull (once)."""
    from tollgate.feed import Puller, build_feed_app, publish

    feed_dir = _opt("--dir", "feed")
    if sub == "serve":
        import uvicorn
        port = int(_opt("--port", "8090"))
        print(f"Tollgate feed on http://127.0.0.1:{port}/bundle.json  (source {feed_dir}/bundle_src.yaml)", flush=True)
        uvicorn.run(build_feed_app(feed_dir), host="127.0.0.1", port=port, log_level="warning")
        return 0
    if sub == "publish" and _opt("--add"):
        print(f"published, feed version {publish(feed_dir, _opt('--add'))}")
        return 0
    if sub == "pull":
        import asyncio
        import json

        from tollgate.gateway.policy import DEFAULT_PATH, load_policy
        data = load_policy(_opt("--policy") or DEFAULT_PATH).data
        url = _opt("--url") or (data.get("feed") or {}).get("url") or "http://127.0.0.1:8090/bundle.json"
        target = (data.get("content") or {}).get("signatures") or "signatures.yaml"
        puller = Puller(url)
        wrote = asyncio.run(puller.pull(target))
        print(json.dumps({**puller.state, "wrote": wrote, "target": target}))
        return 0 if puller.state["last_error"] is None else 1
    print("usage: tollgate feed {serve [--port 8090] [--dir feed]|publish --add 'id=..,pattern=..,action=block,tags=A;B'"
          " [--dir feed]|pull [--url U] [--policy F]}", file=sys.stderr)
    return 2


def up() -> int:
    """AC1 one command: gateway (in-process, with /console and /edge) + feed server (subprocess, if `feed:` is set)."""
    import subprocess
    from urllib.parse import urlparse

    from tollgate.gateway.policy import DEFAULT_PATH, load_policy

    procs = []
    url = (load_policy(_opt("--policy") or DEFAULT_PATH).data.get("feed") or {}).get("url")
    if url:
        procs.append(subprocess.Popen([sys.executable, "-m", "tollgate.cli", "feed", "serve",
                                       "--port", str(urlparse(url).port or 8090)]))
    try:
        return serve()
    finally:
        for p in procs:
            p.terminate()
            p.wait(10)


def key_issue() -> int:
    from tollgate.gateway.keys import issue

    role, key_id = _opt("--role"), _opt("--key-id")
    if not role or "_" in role + (key_id or ""):
        print("usage: tollgate key issue --role R [--key-id K] [--port P]", file=sys.stderr)
        return 2
    key = issue(role, key_id)
    print(key)
    print("warning: an unenrolled key; every door refuses it unless the policy sets allow_unenrolled_keys: true. "
          "Per-laptop keys: tollgate enroll, then tollgate connect <agent>.", file=sys.stderr)
    base = f"http://127.0.0.1:{_opt('--port', '8080')}"
    print(f"MCP URL: {base}/mcp/{role}/")
    print(f"Model door: {base}/v1/chat/completions")
    print(f"Header:  Authorization: Bearer {key}")
    return 0


def open_ui(args: list[str]) -> int:
    """`tollgate open [edge|console] [TRACE_ID] [--port N]`: browser on the UI, or on one step's details."""
    import webbrowser

    from tollgate import edge, explain

    pos = [a for i, a in enumerate(args) if not a.startswith("--") and (i == 0 or args[i - 1] != "--port")]
    ui = pos.pop(0) if pos and pos[0] in ("edge", "console") else "edge"
    base = f"http://127.0.0.1:{_opt('--port', '8080')}"
    url = f"{base}/{ui}/"
    if pos:
        ev = next((e for e in reversed(edge.load_events()) if e.get("trace_id") == pos[0]), None)
        if not ev:
            print(f"trace {pos[0]} not in the audit log", file=sys.stderr)
            return 1
        url = explain.details_url(base, edge._sid(ev), pos[0], ui)
    print(url)  # headless: copy it by hand
    webbrowser.open(url)
    return 0


def enroll_token() -> int:
    from tollgate.gateway import peers
    t = peers.enroll_token()
    print(f"tollgate enroll {t['token']} --owner <name> --device <name>")
    print(f"one-time, expires {t['expires_at']}")
    return 0


def enroll(token: str) -> int:
    """ponytail: writes the hub's registry directly (hub and laptop share a disk in the demo); POST to the hub later."""
    from tollgate.gateway import peers
    owner, device = _opt("--owner"), _opt("--device")
    if not owner or not device:
        print("usage: tollgate enroll <token> --owner O --device D", file=sys.stderr)
        return 2
    try:
        pid = peers.enroll(token, owner, device)
    except ValueError as e:
        print(e, file=sys.stderr)
        return 1
    print(f"enrolled {device} ({owner}) as peer {pid}; the admin sets its roles in the console (Peers & roles)")
    return 0


def connect(client: str) -> int:
    """Mints a key for one agent launch and prints (or with --write merges) that agent's MCP entry + hooks."""
    from pathlib import Path

    from tollgate import connect as conn
    from tollgate.gateway import peers
    from tollgate.gateway.policy import DEFAULT_PATH, load_policy

    role, pid = _opt("--role"), _opt("--peer")
    if client not in (*conn.AGENTS, "print") or not role or not pid:
        print(f"usage: tollgate connect {'|'.join(conn.AGENTS)}|print --role R --peer P [--port N] [--host H]"
              " [--write [--dir PATH]] [--fast]", file=sys.stderr)
        return 2
    try:
        key = peers.mint(pid, role, load_policy(_opt("--policy") or DEFAULT_PATH).data["roles"])
    except KeyError:
        print(f"refused: unknown peer {pid}", file=sys.stderr)
        return 1
    except ValueError as e:
        print(f"refused: {e}", file=sys.stderr)
        return 1
    base = f"http://{_opt('--host', '127.0.0.1')}:{_opt('--port', '8080')}"
    if client == "print":
        print(key)
        print(f"MCP URL: {base}/mcp/{role}/")
        print(f"Model door: {base}/v1/chat/completions")
        print(f"Header:  Authorization: Bearer {key}")
        return 0
    where = None
    if "--write" in sys.argv:
        where = Path(_opt("--dir") or (Path.home() / ".hermes" if client == "hermes" else "."))
    try:
        print(conn.connect(client, key, role, base, where, fast="--fast" in sys.argv))
    except ValueError as e:  # TOML/JSON in the user's file we can't merge into: nothing was written
        print(f"not written: {e}", file=sys.stderr)
        return 1
    return 0


# owner, device, roles, scenario steps (scenario/acme.yaml) its agents run; each fresh session is one launch = one key
FLEET = [
    ("Andrey Mazurchuk", "andrey-thinkpad", ["role-2"], ["3.1", "3.2", "3.3", "3.4a", "3.4b"]),
    ("Marta Kowalska", "marta-macbook", ["role-2"], ["2.1", "2.2", "2.3", "2.4", "2.5"]),
    ("Piotr Nowak", "piotr-xps", ["role-1"], ["1.1", "1.2"]),
    ("Ola Wiśniewska", "ola-surface", ["role-1", "role-2"], ["1.1", "3.5a", "3.5b", "3.5c"]),
    ("Tomasz Zieliński", "tomek-mbp", ["role-2"], ["3.4a", "3.4b", "2.1", "2.2", "5.1"]),
    ("Kasia Lewandowska", "kasia-x1", ["role-1"], ["1.1", "1.2"]),
]


def seed_fleet() -> int:
    """Enrolls the demo fleet (reused by device on reruns) and drives its traffic through the real in-process gateway
    with minted keys into the shared audit log, so every console number is a real decision."""
    import asyncio
    import os

    from tollgate import scenario
    from tollgate.gateway import build_app, peers
    from tollgate.gateway.policy import DEFAULT_PATH, load_policy

    os.environ.setdefault("TOLLGATE_UPSTREAM", "scripted")
    os.environ.setdefault("TOLLGATE_T2", "off")  # the classifier is a 739 MB download; TOLLGATE_T2=on to include it
    holder = load_policy(_opt("--policy") or DEFAULT_PATH)
    app = build_app(holder)

    class Fleet(scenario.Runner):
        def __init__(self, pid):
            super().__init__(app)
            self.pid = pid

        def key(self, step):  # one minted key per scenario session, as one agent launch would get
            sess = step["session"]
            if sess not in self.keys:
                self.keys[sess] = peers.mint(self.pid, self.spec["agents"][step["agent"]]["role"], holder.data["roles"])
            return self.keys[sess]

    async def go():
        async with app.router.lifespan_context(app):
            for owner, device, roles, steps in FLEET:
                pid = next((i for i, p in peers.load()["peers"].items()
                            if p["device"] == device and not p["revoked_at"]), None)
                if pid is None:
                    pid = peers.enroll(peers.enroll_token()["token"], owner, device)
                    peers.set_roles(pid, roles)
                r = Fleet(pid)
                r.reset()
                res = [await r.run(s) for s in steps]
                print(f"{pid} {device:16} {owner:20} " + " ".join(f"{x['id']}:{x['status']}" for x in res))
    asyncio.run(go())
    return 0


USAGE = {  # one line per subcommand; `tollgate <cmd> --help` prints its line and exits before doing anything
    "up": "up [--port 8080] [--policy F] [--scripted-model]   gateway + /console + /edge (+ feed server if `feed:` is set)",
    "serve": "serve [--port 8080] [--policy F] [--scripted-model]   gateway only",
    "agent": "agent [--role R] [--model M] [--base URL] [--scripted] [TASK]   demo agent (--scripted: in-process)",
    "replay": "replay github|supabase   attack trace, taint off then on (in-process)",
    "test": "test [--eval-only] [PYTEST ARGS]   test suite + eval report",
    "perf": "perf [--n 200]   latency per stage (writes audit/perf.json)",
    "approve": "approve ID [--port P]   approve a parked call",
    "deny": "deny ID [--port P]   deny a parked call",
    "key": "key issue --role R [--key-id K] [--port P]   hand-issued key (dev; needs allow_unenrolled_keys: true)",
    "enroll-token": "enroll-token   one-time token to enroll a laptop",
    "enroll": "enroll TOKEN --owner O --device D   enroll this laptop",
    "connect": "connect claude-code|codex|cursor|gemini|hermes|print --role R --peer P [--port P] [--host H] [--policy F]"
               " [--write [--dir PATH]] [--fast]   mint a key per agent launch + that agent's config",
    "hook": "hook AGENT [EVENT] [--url http://127.0.0.1:8080]   hook shim (agent JSON on stdin)",
    "open": "open [edge|console] [TRACE_ID] [--port N]   open a UI or one step's details",
    "seed-fleet": "seed-fleet [--policy F]   demo fleet traffic through the real gateway",
    "admin": "admin create --email E [--name N] [--password-stdin] | invite --email E [--role viewer|admin] | list | disable --email E",
    "feed": "feed serve [--port 8090] [--dir feed] | publish --add 'id=..,pattern=..,action=block,tags=A;B' | pull [--url U]",
}


def usage(cmd: str | None = None) -> str:
    if cmd in USAGE:
        return "usage: tollgate " + USAGE[cmd]
    return "usage: tollgate <command> [options]   (tollgate <command> --help)\n" + "\n".join(
        "  " + u for u in dict.fromkeys(USAGE.values()))

def admin(sub: str) -> int:
    """Console accounts: create (first admin) | invite | list | disable. Works on the store directly (same machine)."""
    import getpass

    from tollgate import accounts
    try:
        if sub == "create":
            if "--password-stdin" in sys.argv:
                pw = sys.stdin.readline().rstrip(chr(13) + chr(10))
            else:
                pw = getpass.getpass("Password (12+ characters): ")
                if getpass.getpass("Again: ") != pw:
                    print("The passwords differ.", file=sys.stderr)
                    return 1
            u = accounts.create_user(_opt("--email"), pw, _opt("--role", "admin"), _opt("--name"))
            accounts.log("cli", f"Created {u['email']} as {u['role']}")
            print(f"Created {u['email']} ({u['role']}). Sign in at /console/.")
        elif sub == "invite":
            t = accounts.invite(_opt("--email"), _opt("--role", "viewer"), "cli")
            base = _opt("--url") or f"http://127.0.0.1:{_opt('--port', '8080')}"
            print(f"{base}/console/#/accept/{t['token']}\nOne use, for {t['email']} ({t['role']}). Expires {t['expires_at']}.")
        elif sub == "list":
            for u in accounts.listing():
                print(f"{u['email']:32} {u['role']:7} {'disabled' if u['disabled'] else 'active':9} "
                      f"last login {u['last_login'] or 'never'}  {u['name']}")
        elif sub == "disable":
            accounts.set_disabled(accounts.norm_email(_opt("--email")), True, "cli")
            print("Disabled; their sessions are signed out.")
        else:
            print("usage: tollgate admin create --email E [--name N] [--password-stdin] | invite --email E "
                  "[--role viewer|admin] [--url BASE] | list | disable --email E", file=sys.stderr)
            return 2
    except (ValueError, KeyError) as e:
        print(f"Refused: {e}", file=sys.stderr)
        return 1
    return 0


def main() -> int:
    sys.stdout.reconfigure(encoding="utf-8")  # Windows consoles default to cp1252 and mangle "…" in redactions
    cmd = sys.argv[1] if len(sys.argv) > 1 else ""
    if "-h" in sys.argv[1:] or "--help" in sys.argv[1:]:  # before anything runs: `up --help` must not start a server
        print(usage(cmd))
        return 0
    if cmd == "test":
        args = sys.argv[2:]
        rc = 0
        if "--eval-only" in args:
            args.remove("--eval-only")
        else:
            import pytest
            from pathlib import Path
            root = Path(__file__).resolve().parents[1]  # collect the repo's tests, not the CWD's
            from tollgate.eval.runner import Tally
            rc = pytest.main(["-q", "--rootdir", str(root), str(root / "tests"), *args], plugins=[Tally()])
        from tollgate.eval.runner import main as evaluate
        print("\n== tollgate eval ==")
        evaluate()
        return int(rc)
    if cmd == "replay" and sys.argv[2:3] in (["github"], ["supabase"]):
        return replay(sys.argv[2])
    if cmd == "perf":
        from tollgate.gateway.perf import main as perf
        return perf(int(_opt("--n", "200")))
    if cmd == "serve":
        return serve()
    if cmd == "agent":
        return agent()
    if cmd == "key" and sys.argv[2:3] == ["issue"]:
        return key_issue()
    if cmd in ("approve", "deny") and len(sys.argv) > 2:
        return decide(sys.argv[2], cmd)
    if cmd == "up":
        return up()
    if cmd == "enroll-token":
        return enroll_token()
    if cmd == "enroll" and len(sys.argv) > 2:
        return enroll(sys.argv[2])
    if cmd == "connect" and len(sys.argv) > 2:
        return connect(sys.argv[2])
    if cmd == "hook":
        from tollgate.connect import main as hook
        return hook(sys.argv[2:])
    if cmd == "open":
        return open_ui(sys.argv[2:])
    if cmd == "admin":
        return admin(sys.argv[2] if len(sys.argv) > 2 else "")
    if cmd == "seed-fleet":
        return seed_fleet()
    if cmd == "feed":
        return feed(sys.argv[2] if len(sys.argv) > 2 else "")
    print(usage(), file=sys.stderr)
    return 2


if __name__ == "__main__":
    sys.exit(main())
