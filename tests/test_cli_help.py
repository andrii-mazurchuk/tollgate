"""`tollgate <cmd> --help` prints usage and exits 0 before anything runs (no server, no agent, no key minted)."""
import sys

import pytest

from tollgate import cli


@pytest.mark.parametrize("cmd", [*cli.USAGE, ""])
def test_help_runs_nothing(cmd, monkeypatch, capsys):
    for name in ("replay", "serve", "agent", "decide", "feed", "up", "key_issue", "open_ui", "enroll_token", "enroll",
                 "connect", "seed_fleet"):
        monkeypatch.setattr(cli, name, lambda *a, **k: pytest.fail("ran instead of printing help"))
    monkeypatch.setattr(sys, "argv", ["tollgate", *([cmd] if cmd else []), "x", "--help"])
    assert cli.main() == 0
    assert capsys.readouterr().out.startswith("usage: tollgate")
