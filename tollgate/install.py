"""Installed-mode helpers: `tollgate init`, `tollgate doctor`, `tollgate service install|uninstall|status`.

Service files are generated as text and only written / registered with --yes (dry run by default). Per OS:
Linux a systemd --user unit, macOS a launchd agent, Windows a Scheduled Task at logon (pythonw = no console window).
"""
import json
import os
import re
import shutil
import subprocess
import sys
import urllib.request
from pathlib import Path
from xml.sax.saxutils import escape

from tollgate import paths

LABEL = "com.tollgate.hub"  # launchd label; the systemd unit is tollgate.service, the Windows task "Tollgate"


def init(force: bool = False) -> str:
    """Creates HOME and HOME/audit, copies the packaged defaults (never over an existing file without --force, which
    keeps a .bak), creates the install secret. Idempotent."""
    from tollgate.gateway import keys

    out = [f"Tollgate home: {paths.HOME}"]
    paths.AUDIT.mkdir(parents=True, exist_ok=True)
    for name in paths.DEFAULTS:
        src, dst = paths.default(name), paths.HOME / name
        if dst.exists() and (src.resolve() == dst.resolve() or not force):
            out.append(f"  kept    {dst}")
            continue
        if dst.exists():  # --force: keep the user's edits next to the fresh default
            bak = dst.with_name(dst.name + ".bak")
            shutil.rmtree(bak) if bak.is_dir() else bak.unlink(missing_ok=True)
            dst.rename(bak)
            out.append(f"  backup  {bak}")
        shutil.copytree(src, dst) if src.is_dir() else shutil.copyfile(src, dst)
        out.append(f"  created {dst}")
    secret = Path(os.environ.get("TOLLGATE_SECRET_FILE") or keys.SECRET_FILE)
    existed = secret.exists()
    keys.install_secret()
    out.append(f"  {'kept   ' if existed else 'created'} {secret}")
    out += ["", "Next steps:",
            "  tollgate up                                   # the hub: http://127.0.0.1:8080/console/",
            "  tollgate service install --yes                # optional: start the hub at logon",
            "  tollgate admin create --email you@example.com # the console owner",
            "  tollgate enroll-token  ->  tollgate enroll <token> --owner <you> --device <laptop>",
            "  (console: give the peer a role)  ->  tollgate connect claude-code --role R --peer P --scope user --write",
            "  tollgate doctor"]
    return "\n".join(out)


# ---------------------------------------------------------------- doctor

AGENT_FILES = {  # where each agent's Tollgate config lives: (user scope, project scope), relative to ~ / the CWD
    "claude-code": ((".claude/settings.json", ".claude.json"), (".claude/settings.json", ".mcp.json")),
    "codex": ((".codex/config.toml",), (".codex/config.toml",)),
    "cursor": ((".cursor/mcp.json", ".cursor/hooks.json"), (".cursor/mcp.json", ".cursor/hooks.json")),
    "gemini": ((".gemini/settings.json",), (".gemini/settings.json",)),
    "hermes": ((".hermes/config.yaml",), ()),
}


def _configured(f: Path) -> bool:
    """A Tollgate MCP entry or hook in an agent config (not just the word, e.g. a project path in ~/.claude.json)."""
    try:
        text = f.read_text(encoding="utf-8", errors="replace") if f.is_file() else ""
    except OSError:
        return False
    if f.name == ".claude.json":  # user-scope servers are its top-level mcpServers; projects.* are local scope
        try:
            return "tollgate" in (json.loads(text).get("mcpServers") or {})
        except (ValueError, AttributeError):
            return False
    return "tollgate.cli hook" in text or re.search(r'(^|["\[.\s])tollgate("?\s*:|\])', text, re.M) is not None


def doctor(port: int = 8080, cwd: Path | None = None) -> tuple[str, int]:
    """(report, exit code): OK/WARN/FAIL lines; exit 1 on any FAIL."""
    from tollgate import accounts
    from tollgate.gateway import keys
    from tollgate.gateway.policy import DEFAULT_PATH, load_policy

    cwd, rows = cwd or Path.cwd(), []
    add = lambda level, msg: rows.append((level, msg))  # noqa: E731
    v = sys.version_info
    add("OK" if v >= (3, 13) else "FAIL", f"python {v.major}.{v.minor}.{v.micro} ({sys.executable})")
    exe = shutil.which("tollgate")
    add("OK" if exe else "WARN", f"tollgate on PATH: {exe or 'no (add the install bin dir to PATH)'}; "
        f"mode: {'source checkout' if paths.checkout() else 'installed'}")
    home_ok = paths.HOME.is_dir() and os.access(paths.HOME, os.W_OK)
    add("OK" if home_ok else "FAIL", f"home {paths.HOME} {'writable' if home_ok else 'missing or read-only (tollgate init)'}")
    try:
        add("OK", f"policy {DEFAULT_PATH} valid (version {load_policy(DEFAULT_PATH).status()['version']})")
    except FileNotFoundError:
        add("FAIL", f"policy {DEFAULT_PATH} missing (tollgate init)")
    except Exception as e:  # noqa: BLE001 - any validation error
        add("FAIL", f"policy {DEFAULT_PATH} invalid: {e}")
    secret = Path(os.environ.get("TOLLGATE_SECRET_FILE") or keys.SECRET_FILE)
    add("OK" if secret.exists() or os.environ.get("TOLLGATE_KEY_SECRET") else "WARN",
        f"install secret {secret} {'present' if secret.exists() else 'missing (tollgate init)'}")
    try:
        with urllib.request.urlopen(f"http://127.0.0.1:{port}/healthz", timeout=2) as r:
            add("OK" if json.loads(r.read() or b'{}').get("ok") else "WARN", f"hub on 127.0.0.1:{port} answers /healthz")
    except Exception as e:  # noqa: BLE001
        add("WARN", f"hub on 127.0.0.1:{port} not reachable ({getattr(e, 'reason', e)}): tollgate up --port {port}")
    try:
        admins = [u for u in accounts.listing() if u["role"] == "admin" and not u["disabled"]]
        add("OK" if admins else "WARN", f"console owner: {admins[0]['email'] if admins else 'none (tollgate admin create --email E)'}")
    except Exception as e:  # noqa: BLE001
        add("WARN", f"console accounts unreadable: {e}")
    for agent, (user, project) in AGENT_FILES.items():
        hits = [f"~/{p}" for p in user if _configured(Path.home() / p)] + [p for p in project if _configured(cwd / p)]
        add("OK" if hits else "WARN", f"{agent}: {'configured in ' + ', '.join(hits) if hits else 'not configured'}")
    add("OK" if os.environ.get("TOLLGATE_KEY") else "WARN",
        "TOLLGATE_KEY " + ("set" if os.environ.get("TOLLGATE_KEY") else "not set in this shell (tollgate connect prints it)"))
    return "\n".join(f"{lvl:4}  {msg}" for lvl, msg in rows), int(any(lvl == "FAIL" for lvl, _ in rows))


# ---------------------------------------------------------------- service

def _argv(port: int, windowless: bool = False) -> list[str]:
    py = Path(sys.executable)
    if windowless and py.with_name("pythonw.exe").exists():
        py = py.with_name("pythonw.exe")
    return [str(py), "-m", "tollgate.cli", "up", "--port", str(port), "--home", str(paths.HOME)]


def systemd_unit(argv: list[str]) -> str:
    cmd = " ".join(f'"{a}"' if " " in a else a for a in argv)
    return ("[Unit]\nDescription=Tollgate hub\nAfter=network.target\n\n"
            f"[Service]\nExecStart={cmd}\nRestart=on-failure\n\n[Install]\nWantedBy=default.target\n")


def launchd_plist(argv: list[str], log: Path) -> str:
    args = "".join(f"\n    <string>{escape(a)}</string>" for a in argv)
    return ('<?xml version="1.0" encoding="UTF-8"?>\n'
            '<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">\n'
            f'<plist version="1.0">\n<dict>\n  <key>Label</key>\n  <string>{LABEL}</string>\n'
            f"  <key>ProgramArguments</key>\n  <array>{args}\n  </array>\n"
            "  <key>RunAtLoad</key>\n  <true/>\n  <key>KeepAlive</key>\n  <true/>\n"
            f"  <key>StandardOutPath</key>\n  <string>{escape(str(log))}</string>\n"
            f"  <key>StandardErrorPath</key>\n  <string>{escape(str(log))}</string>\n</dict>\n</plist>\n")


def task_xml(argv: list[str], user: str) -> str:
    args = subprocess.list2cmdline(argv[1:])
    return ('<?xml version="1.0" encoding="UTF-16"?>\n'
            '<Task version="1.2" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">\n'
            "  <RegistrationInfo><Description>Tollgate hub (tollgate service install)</Description></RegistrationInfo>\n"
            f"  <Triggers><LogonTrigger><Enabled>true</Enabled><UserId>{escape(user)}</UserId></LogonTrigger></Triggers>\n"
            f'  <Principals><Principal id="Author"><UserId>{escape(user)}</UserId><LogonType>InteractiveToken</LogonType>'
            "<RunLevel>LeastPrivilege</RunLevel></Principal></Principals>\n"
            "  <Settings><MultipleInstancesPolicy>IgnoreNew</MultipleInstancesPolicy>"
            "<DisallowStartIfOnBatteries>false</DisallowStartIfOnBatteries><StopIfGoingOnBatteries>false</StopIfGoingOnBatteries>"
            "<ExecutionTimeLimit>PT0S</ExecutionTimeLimit><Hidden>true</Hidden>"
            "<RestartOnFailure><Interval>PT1M</Interval><Count>3</Count></RestartOnFailure></Settings>\n"
            f'  <Actions Context="Author"><Exec><Command>{escape(argv[0])}</Command><Arguments>{escape(args)}</Arguments>'
            "</Exec></Actions>\n</Task>\n")


def service_plan(action: str, port: int, platform: str = sys.platform) -> tuple[Path | None, str | None, list[list[str]]]:
    """(file to write or delete, its text for install, commands to run)."""
    if platform == "win32":
        f = paths.AUDIT / "tollgate-task.xml"
        user = f"{os.environ.get('USERDOMAIN', '')}\\{os.environ.get('USERNAME', '')}".lstrip("\\")
        return {"install": (f, task_xml(_argv(port, True), user),
                            [["schtasks", "/Create", "/TN", "Tollgate", "/XML", str(f), "/F"], ["schtasks", "/Run", "/TN", "Tollgate"]]),
                "uninstall": (f, None, [["schtasks", "/End", "/TN", "Tollgate"], ["schtasks", "/Delete", "/TN", "Tollgate", "/F"]]),
                "status": (None, None, [["schtasks", "/Query", "/TN", "Tollgate", "/FO", "LIST"]])}[action]
    if platform == "darwin":
        f = Path.home() / "Library" / "LaunchAgents" / f"{LABEL}.plist"
        dom = f"gui/{os.getuid() if hasattr(os, 'getuid') else '$UID'}"
        return {"install": (f, launchd_plist(_argv(port), paths.AUDIT / "hub.log"), [["launchctl", "bootstrap", dom, str(f)]]),
                "uninstall": (f, None, [["launchctl", "bootout", f"{dom}/{LABEL}"]]),
                "status": (None, None, [["launchctl", "print", f"{dom}/{LABEL}"]])}[action]
    f = Path(os.environ.get("XDG_CONFIG_HOME") or Path.home() / ".config") / "systemd" / "user" / "tollgate.service"
    sc = ["systemctl", "--user"]
    return {"install": (f, systemd_unit(_argv(port)), [[*sc, "daemon-reload"], [*sc, "enable", "--now", "tollgate.service"]]),
            "uninstall": (f, None, [[*sc, "disable", "--now", "tollgate.service"], [*sc, "daemon-reload"]]),
            "status": (None, None, [[*sc, "status", "tollgate.service", "--no-pager"]])}[action]


def service(action: str, port: int, apply: bool) -> int:
    f, text, cmds = service_plan(action, port)
    if action == "status":
        return subprocess.call(cmds[0])  # read-only
    if f and text is not None:
        print(f"will write {f}:\n{text}")
    elif f:
        print(f"will delete {f}")
    for c in cmds:
        print("will run: " + subprocess.list2cmdline(c))
    if not apply:
        print("\nDry run: nothing was changed. Re-run with --yes to apply.")
        return 0
    if text is not None:
        f.parent.mkdir(parents=True, exist_ok=True)
        f.write_text(text, encoding="utf-16" if f.suffix == ".xml" else "utf-8")
        paths.AUDIT.mkdir(parents=True, exist_ok=True)
    rc = 0
    for c in cmds:
        r = subprocess.call(c)
        if r and not (action == "uninstall" and c is not cmds[-1]):  # stopping an already-stopped service is fine
            rc = r
    if action == "uninstall" and f:
        f.unlink(missing_ok=True)
    return rc
