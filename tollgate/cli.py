"""`tollgate` command. Subcommands land as tracks build them (up/serve/dashboard/approve/deny/replay/key: A, test: B)."""
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
        print(f"  {role}: {base}/mcp/{role}/   (key: tollgate key issue --role {role})")
    import os

    from tollgate.gateway.model_door import DEFAULT_UPSTREAM
    print(f"  model door: {base}/v1/chat/completions  -> {os.environ.get('TOLLGATE_UPSTREAM') or DEFAULT_UPSTREAM}")
    print(f"  health: {base}/healthz   taint: {base}/admin/taint   budget: {base}/admin/budget", flush=True)
    print(f"  approvals: {base}/admin/approvals   (tollgate approve|deny <id>)", flush=True)
    uvicorn.run(app, host="127.0.0.1", port=port, log_level="warning")
    return 0


def agent() -> int:
    """Demo agent through both doors. --scripted without --base: in-process gateway + scripted hijacked model."""
    import asyncio

    import httpx2

    from tollgate.agent import run
    from tollgate.gateway.keys import issue

    rest, i = sys.argv[2:], 0
    while i < len(rest) and rest[i].startswith("--"):
        i += 1 if rest[i] == "--scripted" else 2
    task = rest[i] if i < len(rest) else "check the open issues on acme/website and handle them"
    role, model, base = _opt("--role", "role-2"), _opt("--model", "qwen3:4b"), _opt("--base")
    key = issue(role)
    print(f"[agent] role={role} model={model} task={task!r}")
    if base or "--scripted" not in sys.argv:
        asyncio.run(run(task, role, model, base or "http://127.0.0.1:8080", key))
        return 0

    import os

    from tollgate.gateway import build_app
    from tollgate.gateway.policy import DEFAULT_PATH, load_policy

    os.environ["TOLLGATE_UPSTREAM"] = "scripted"
    app = build_app(load_policy(_opt("--policy") or DEFAULT_PATH))

    def factory(**kw):
        return httpx2.AsyncClient(transport=httpx2.ASGITransport(app=app), base_url="http://t", **kw)

    async def go():
        async with app.router.lifespan_context(app):
            await run(task, role, model, "http://t", key, factory=factory)
    asyncio.run(go())
    return 0


def decide(id: str, decision: str) -> int:
    """POST /admin/approvals/{id} with the admin token (env TOLLGATE_ADMIN_TOKEN, else the dev constant)."""
    import json
    import os
    import urllib.error
    import urllib.request

    from tollgate.gateway.approvals import ADMIN_DEV_TOKEN

    req = urllib.request.Request(
        f"http://127.0.0.1:{_opt('--port', '8080')}/admin/approvals/{id}", method="POST",
        data=json.dumps({"decision": decision}).encode(),
        headers={"Content-Type": "application/json",
                 "Authorization": f"Bearer {os.environ.get('TOLLGATE_ADMIN_TOKEN') or ADMIN_DEV_TOKEN}"})
    try:
        with urllib.request.urlopen(req, timeout=10) as r:
            print(r.read().decode())
            return 0
    except urllib.error.HTTPError as e:
        print(f"{e.code}: {e.read().decode()}", file=sys.stderr)
        return 1


DASHBOARD = ["-m", "streamlit", "run", "dashboard/app.py", "--server.headless", "true", "--server.address", "127.0.0.1",
             "--browser.gatherUsageStats", "false", "--server.port"]


def dashboard(wait: bool = True):
    """Streamlit dashboard as a subprocess of this Python. wait=False returns the Popen (used by `up`)."""
    import subprocess
    from pathlib import Path

    port = _opt("--dashboard-port", "8501")
    p = subprocess.Popen([sys.executable, *DASHBOARD, port], cwd=Path(__file__).resolve().parents[1])
    print(f"  dashboard: http://127.0.0.1:{port}", flush=True)
    return p.wait() if wait else p


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
    """AC1 one command: gateway (in-process) + dashboard (subprocess) + feed server (subprocess, if `feed:` is set)."""
    import subprocess
    from urllib.parse import urlparse

    from tollgate.gateway.policy import DEFAULT_PATH, load_policy

    procs = [dashboard(wait=False)]
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
    base = f"http://127.0.0.1:{_opt('--port', '8080')}"
    print(f"MCP URL: {base}/mcp/{role}/")
    print(f"Model door: {base}/v1/chat/completions")
    print(f"Header:  Authorization: Bearer {key}")
    return 0


def main() -> int:
    sys.stdout.reconfigure(encoding="utf-8")  # Windows consoles default to cp1252 and mangle "…" in redactions
    cmd = sys.argv[1] if len(sys.argv) > 1 else ""
    if cmd == "test":
        args = sys.argv[2:]
        rc = 0
        if "--eval-only" in args:
            args.remove("--eval-only")
        else:
            import pytest
            from pathlib import Path
            root = Path(__file__).resolve().parents[1]  # collect the repo's tests, not the CWD's
            rc = pytest.main(["-q", "--rootdir", str(root), str(root / "tests"), *args])
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
    if cmd == "dashboard":
        return dashboard()
    if cmd == "feed":
        return feed(sys.argv[2] if len(sys.argv) > 2 else "")
    print("usage: tollgate {up [--port P] [--policy F] [--dashboard-port D]|serve [--port P] [--policy F] [--scripted-model]"
          "|agent [--role R] [--model M] [--base URL] [--scripted] TASK|dashboard"
          "|approve ID|deny ID [--port P]|test|replay github|supabase|perf [--n N]|key issue --role R [--key-id K]|feed serve|publish|pull}",
          file=sys.stderr)
    return 2


if __name__ == "__main__":
    sys.exit(main())
