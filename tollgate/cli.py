"""`tollgate` command. Subcommands land as tracks build them (serve: A, test: B, replay: A, key: A)."""
import sys


def main() -> int:
    cmd = sys.argv[1] if len(sys.argv) > 1 else ""
    if cmd == "test":
        import pytest
        return pytest.main(["-q", *sys.argv[2:]])
    print("usage: tollgate {serve|test|replay|key}  (only `test` is wired yet)", file=sys.stderr)
    return 2


if __name__ == "__main__":
    sys.exit(main())
