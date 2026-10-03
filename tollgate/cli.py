"""`tollgate` command. Subcommands land as tracks build them (serve: A, test: B, replay: A, key: A)."""
import sys


def replay_github() -> int:
    """Runs the GitHub attack trace as role-2 with taint off, then on. In-process, no server needed."""
    import asyncio
    import copy

    from mocks.github import PRS
    from tollgate.gateway.policy import PolicyHolder, load_policy
    from tollgate.gateway.replay import GITHUB_TRACE, run_trace

    on = load_policy()
    off = copy.deepcopy(on.data)
    off.setdefault("taint", {})["enabled"] = False
    for label, policy in (("taint OFF (roles only)", PolicyHolder(off)), ("taint ON", on)):
        PRS.clear()
        print(f"== {label} ==")
        for i, ((tool, args), s) in enumerate(zip(GITHUB_TRACE, asyncio.run(run_trace(policy, GITHUB_TRACE))), 1):
            shown = {k: v for k, v in args.items() if k != "body"}
            print(f"  {i}. {tool} {shown} -> {s['verdict'].upper()}: {s['text'].strip().splitlines()[0][:170]}")
        print(f"  PRs created: {len(PRS)}" + (f", body leaks: {PRS[0]['body'].strip().splitlines()[-2:]}" if PRS else ""))
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
    app = build_app(holder)
    base = f"http://127.0.0.1:{port}"
    print(f"Tollgate on {base}  policy {holder.status()['version']} ({holder.path})")
    for role in holder.data["roles"]:
        print(f"  {role}: {base}/mcp/{role}/   (key: tollgate key issue --role {role})")
    import os

    from tollgate.gateway.model_door import DEFAULT_UPSTREAM
    print(f"  model door: {base}/v1/chat/completions  -> {os.environ.get('TOLLGATE_UPSTREAM') or DEFAULT_UPSTREAM}")
    print(f"  health: {base}/healthz   taint: {base}/admin/taint   budget: {base}/admin/budget", flush=True)
    uvicorn.run(app, host="127.0.0.1", port=port, log_level="warning")
    return 0


def key_issue() -> int:
    from tollgate.gateway.keys import issue

    role, key_id = _opt("--role"), _opt("--key-id")
    if not role or "_" in role + (key_id or ""):
        print("usage: tollgate key issue --role R [--key-id K] [--port P]", file=sys.stderr)
        return 2
    key = issue(role, key_id)
    print(key)
    print(f"MCP URL: http://127.0.0.1:{_opt('--port', '8080')}/mcp/{role}/")
    print(f"Header:  Authorization: Bearer {key}")
    return 0


def main() -> int:
    cmd = sys.argv[1] if len(sys.argv) > 1 else ""
    if cmd == "test":
        args = sys.argv[2:]
        rc = 0
        if "--eval-only" in args:
            args.remove("--eval-only")
        else:
            import pytest
            rc = pytest.main(["-q", *args])
        from tollgate.eval.runner import main as evaluate
        print("\n== tollgate eval ==")
        evaluate()
        return int(rc)
    if cmd == "replay" and sys.argv[2:3] == ["github"]:
        return replay_github()
    if cmd == "serve":
        return serve()
    if cmd == "key" and sys.argv[2:3] == ["issue"]:
        return key_issue()
    print("usage: tollgate {serve [--port P] [--policy F]|test|replay github|key issue --role R [--key-id K]}",
          file=sys.stderr)
    return 2


if __name__ == "__main__":
    sys.exit(main())
