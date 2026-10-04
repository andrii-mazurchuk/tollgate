"""Where Tollgate keeps its files.

HOME holds the editable policy (policy.yaml, policies/, signatures.yaml) and all state under HOME/audit (events,
peers, accounts, secret.key, policy history, ...). Resolution: env TOLLGATE_HOME, else the source checkout this
package runs from (repo-relative, as in dev, tests and the judges' clone), else a per-user data dir:
Linux $XDG_DATA_HOME/tollgate (~/.local/share/tollgate), macOS ~/Library/Application Support/Tollgate,
Windows %LOCALAPPDATA%\\Tollgate. The per-file env overrides (TOLLGATE_AUDIT, _PEERS, _ACCOUNTS, _SECRET_FILE) win.

Read-only defaults (the files `tollgate init` copies into HOME) ship inside the wheel under
tollgate/_defaults (pyproject force-include); in a checkout they are the repo files themselves.
"""
import os
import sys
from importlib.resources import files
from pathlib import Path

SRC = Path(__file__).resolve().parents[1]
DEFAULTS = ("policy.yaml", "signatures.yaml", "policies")  # what `tollgate init` copies into HOME


def checkout(src: Path = SRC) -> bool:
    return (src / "pyproject.toml").is_file() and (src / ".git").exists()  # .git is a file in a worktree


def user_home(platform: str = sys.platform, env=os.environ) -> Path:
    if platform == "win32":
        return Path(env.get("LOCALAPPDATA") or Path.home() / "AppData" / "Local") / "Tollgate"
    if platform == "darwin":
        return Path.home() / "Library" / "Application Support" / "Tollgate"
    return Path(env.get("XDG_DATA_HOME") or Path.home() / ".local" / "share") / "tollgate"


def home(env=os.environ, src: Path = SRC, platform: str = sys.platform) -> Path:
    if env.get("TOLLGATE_HOME"):
        return Path(env["TOLLGATE_HOME"]).expanduser().resolve()
    return src if checkout(src) else user_home(platform, env)


def default(name: str) -> Path:
    """A packaged default file: the repo's own in a checkout, else the copy inside the installed wheel."""
    return SRC / name if checkout() else Path(str(files("tollgate") / "_defaults" / name))


HOME = home()
AUDIT = HOME / "audit"
