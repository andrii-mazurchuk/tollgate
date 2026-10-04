"""Installed mode: home resolution, `tollgate init`, `doctor`, service file text, `connect --scope user`, the wheel."""
import json
import os
import subprocess
import sys
import tomllib
import xml.etree.ElementTree as ET
from pathlib import Path

import pytest

from tests.test_connect import cli, peer  # noqa: F401  (fixture)
from tollgate import install, paths

REPO = Path(__file__).resolve().parents[1]


# ---------------------------------------------------------------- paths

def test_home_env_wins(tmp_path):
    assert paths.home({"TOLLGATE_HOME": str(tmp_path)}, REPO) == tmp_path.resolve()


def test_home_is_the_checkout_in_dev():
    assert paths.checkout() and paths.home({}) == REPO == paths.SRC


@pytest.mark.parametrize("platform,env,want", [
    ("linux", {"XDG_DATA_HOME": "/x/data"}, Path("/x/data/tollgate")),
    ("linux", {}, Path.home() / ".local/share/tollgate"),
    ("darwin", {}, Path.home() / "Library/Application Support/Tollgate"),
    ("win32", {"LOCALAPPDATA": "C:/Users/u/AppData/Local"}, Path("C:/Users/u/AppData/Local/Tollgate")),
])
def test_home_per_os_when_installed(tmp_path, platform, env, want):
    site = tmp_path / "site-packages"  # an installed package: no pyproject.toml/.git next to it
    site.mkdir()
    assert paths.home(env, site, platform) == want


def test_state_lives_under_home_audit():
    from tollgate import accounts
    from tollgate.gateway import audit, keys, peers, policy
    assert {audit.DEFAULT_PATH.parent, keys.SECRET_FILE.parent, peers.DEFAULT_PATH.parent,
            accounts.DEFAULT_PATH.parent} == {paths.AUDIT}
    assert policy.DEFAULT_PATH == paths.HOME / "policy.yaml"


# ---------------------------------------------------------------- init / doctor

@pytest.fixture
def home(tmp_path, monkeypatch):
    h = tmp_path / "tghome"
    monkeypatch.setattr(paths, "HOME", h)
    monkeypatch.setattr(paths, "AUDIT", h / "audit")
    from tollgate.gateway import policy
    monkeypatch.setattr(policy, "DEFAULT_PATH", h / "policy.yaml")
    monkeypatch.setenv("TOLLGATE_SECRET_FILE", str(h / "audit" / "secret.key"))
    monkeypatch.setenv("HOME", str(tmp_path / "user"))
    monkeypatch.setenv("USERPROFILE", str(tmp_path / "user"))
    return h


def test_init_creates_and_is_idempotent(home):
    out = install.init()
    assert (home / "policy.yaml").read_bytes() == (REPO / "policy.yaml").read_bytes()
    assert (home / "policies" / "strict.yaml").is_file() and (home / "signatures.yaml").is_file()
    assert len((home / "audit" / "secret.key").read_text().strip()) >= 32 and "created" in out
    (home / "policy.yaml").write_text("mine")
    secret = (home / "audit" / "secret.key").read_text()
    out = install.init()
    assert "created" not in out and (home / "policy.yaml").read_text() == "mine"
    assert (home / "audit" / "secret.key").read_text() == secret
    install.init(force=True)
    assert (home / "policy.yaml.bak").read_text() == "mine"
    assert (home / "policy.yaml").read_bytes() == (REPO / "policy.yaml").read_bytes()
    assert (home / "audit" / "secret.key").read_text() == secret  # --force never rotates the secret


def test_doctor_on_temp_home(home, tmp_path):
    report, rc = install.doctor(port=1, cwd=tmp_path)
    assert rc == 1 and "FAIL  policy" in report  # before init
    install.init()
    report, rc = install.doctor(port=1, cwd=tmp_path)
    assert rc == 0, report
    assert "OK    policy" in report and "WARN  hub on 127.0.0.1:1" in report and "WARN  claude-code: not configured" in report
    (tmp_path / ".mcp.json").write_text(json.dumps({"mcpServers": {"tollgate": {}}}))
    (tmp_path / "user").mkdir()
    (tmp_path / "user" / ".claude.json").write_text(json.dumps({"projects": {"C:/x/tollgate": {}}}))
    report, _ = install.doctor(port=1, cwd=tmp_path)
    assert "claude-code: configured in .mcp.json" in report  # ~/.claude.json naming a tollgate *path* is not config


# ---------------------------------------------------------------- service (text only, never installed)

def test_service_texts(home, monkeypatch):
    argv = ["/opt/tg/bin/python", "-m", "tollgate.cli", "up", "--port", "8123", "--home", "/h o/me"]
    unit = install.systemd_unit(argv)
    assert 'ExecStart=/opt/tg/bin/python -m tollgate.cli up --port 8123 --home "/h o/me"' in unit
    assert "WantedBy=default.target" in unit and "Restart=on-failure" in unit
    plist = install.launchd_plist(argv, Path("/h/audit/hub.log"))
    root = ET.fromstring(plist.split("\n", 2)[2])
    assert [s.text for s in root.iter("string")][1:9] == argv
    xml = install.task_xml(["C:/tg/pythonw.exe", *argv[1:]], "PC\\u")
    t = ET.fromstring(xml.split("\n", 1)[1])
    ns = {"t": "http://schemas.microsoft.com/windows/2004/02/mit/task"}
    assert t.find(".//t:Exec/t:Command", ns).text == "C:/tg/pythonw.exe"
    assert t.find(".//t:Exec/t:Arguments", ns).text == '-m tollgate.cli up --port 8123 --home "/h o/me"'
    assert t.find(".//t:LogonTrigger/t:UserId", ns).text == "PC\\u"
    assert t.find(".//t:RunLevel", ns).text == "LeastPrivilege"
    for plat, cmd in (("linux", "systemctl"), ("darwin", "launchctl"), ("win32", "schtasks")):
        f, text, cmds = install.service_plan("install", 8123, plat)
        assert text and cmds[0][0] == cmd and "--port" in text and "8123" in text


def test_service_is_dry_run_without_yes(home, capsys, monkeypatch):
    ran = []
    monkeypatch.setattr(subprocess, "call", lambda c: ran.append(c) or 0)
    assert install.service("install", 8123, apply=False) == 0
    assert ran == [] and "Dry run" in capsys.readouterr().out
    f, _, _ = install.service_plan("install", 8123)
    assert not f.exists()


# ---------------------------------------------------------------- connect --scope user

@pytest.mark.parametrize("agent,files", [
    ("claude-code", [".claude/settings.json"]),
    ("codex", [".codex/config.toml"]),
    ("cursor", [".cursor/mcp.json", ".cursor/hooks.json"]),
    ("gemini", [".gemini/settings.json"]),
])
def test_connect_user_scope_writes_home(monkeypatch, capsys, peer, tmp_path, agent, files):  # noqa: F811
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setenv("USERPROFILE", str(tmp_path))
    (tmp_path / ".claude").mkdir()
    (tmp_path / ".claude/settings.json").write_text(json.dumps({"model": "opus"}))
    for _ in range(2):
        rc, out, err = cli(monkeypatch, capsys, "connect", agent, "--role", "role-2", "--peer", peer,
                           "--scope", "user", "--write")
        assert rc == 0, err
    for f in files:
        assert (tmp_path / f).is_file()
    assert sys.executable.replace("\\", "/") in (tmp_path / files[-1]).read_text()  # hook -> this install
    assert not (tmp_path / ".mcp.json").exists()
    if agent == "claude-code":
        assert json.loads((tmp_path / ".claude/settings.json").read_text())["model"] == "opus"
        assert "claude mcp add --transport http --scope user --header 'Authorization: Bearer ${TOLLGATE_KEY}' " \
               "tollgate http://127.0.0.1:8080/mcp/role-2/" in out
        assert len(json.loads((tmp_path / ".claude/settings.json").read_text())["hooks"]["PreToolUse"]) == 1
    if agent == "codex":
        assert tomllib.loads((tmp_path / files[0]).read_text())["mcp_servers"]["tollgate"]
    assert "setx TOLLGATE_KEY" in out and "~/.bashrc" in out


def test_connect_rejects_bad_scope(monkeypatch, capsys, peer):  # noqa: F811
    rc, _, err = cli(monkeypatch, capsys, "connect", "codex", "--role", "role-2", "--peer", peer, "--scope", "global")
    assert rc == 2 and "--scope project|user" in err


# ---------------------------------------------------------------- the wheel

@pytest.mark.slow
def test_wheel_ships_defaults_and_runs_outside_the_repo(tmp_path):
    """uv build -> fresh venv -> the installed tollgate inits a temp home from the packaged defaults."""
    subprocess.run(["uv", "build", "--wheel", "-o", str(tmp_path / "dist"), str(REPO)], check=True, capture_output=True)
    wheel = next((tmp_path / "dist").glob("tollgate-*.whl"))
    subprocess.run(["uv", "venv", "-q", "--python", "3.13", str(tmp_path / "v")], check=True)
    py = tmp_path / "v" / ("Scripts/python.exe" if os.name == "nt" else "bin/python")
    subprocess.run(["uv", "pip", "install", "-q", "--python", str(py), str(wheel)], check=True)
    env = {k: v for k, v in os.environ.items() if not k.startswith("TOLLGATE_")} | {"TOLLGATE_HOME": str(tmp_path / "h")}
    run = lambda *a: subprocess.run([str(py), "-m", "tollgate.cli", *a], cwd=tmp_path, env=env,  # noqa: E731
                                    capture_output=True, text=True, encoding="utf-8")
    code = ("from importlib.resources import files; from tollgate import paths, scenario; "
            "assert not paths.checkout(); assert (files('tollgate')/'_defaults'/'policies'/'strict.yaml').is_file(); "
            "assert scenario.load()['agents']; import mocks.github")
    assert subprocess.run([str(py), "-c", code], cwd=tmp_path, env=env).returncode == 0
    r = run("init")
    assert r.returncode == 0 and (tmp_path / "h" / "policy.yaml").is_file(), r.stderr
    r = run("doctor", "--port", "1")
    assert r.returncode == 0 and "mode: installed" in r.stdout, r.stdout + r.stderr
