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
    print("usage: tollgate {serve|test|replay|key}  (wired: test, replay github)", file=sys.stderr)
    return 2


if __name__ == "__main__":
    sys.exit(main())
