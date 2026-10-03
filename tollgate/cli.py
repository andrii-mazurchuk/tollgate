"""`tollgate` command. Subcommands land as tracks build them (serve: A, test: B, replay: A, key: A)."""
import sys


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
    print("usage: tollgate {serve|test|replay|key}  (only `test` is wired yet)", file=sys.stderr)
    return 2


if __name__ == "__main__":
    sys.exit(main())
