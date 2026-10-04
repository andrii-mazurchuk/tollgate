#!/bin/sh
# Tollgate installer for Linux and macOS (POSIX sh). No root needed. Re-run = upgrade.
#
#   curl -LsSf https://raw.githubusercontent.com/andrii-mazurchuk/tollgate/main/install.sh | sh
#   sh install.sh [--source PATH|URL] [--ref TAG] [--modify-path] [--install-uv] [--uninstall]
#
#   --source       what to install: a local clone, or a pip/uv spec (default git+https://github.com/andrii-mazurchuk/tollgate)
#   --ref          git tag/branch/commit for a git+ source
#   --modify-path  allow appending the bin dir to ~/.profile (otherwise the line is printed)
#   --install-uv   if neither uv nor Python 3.13+ is found, install uv with its official installer
#   --uninstall    remove the program (your data in the Tollgate home is kept; the path is printed)
#
# Order: uv found -> `uv tool install`; else Python 3.13+ -> venv in <home>/venv + a link in ~/.local/bin;
# else -> print (or with --install-uv run) the uv installer. Then `tollgate init`.
set -eu

SOURCE="git+https://github.com/andrii-mazurchuk/tollgate"
REF=""
MODIFY_PATH=0
INSTALL_UV=0
UNINSTALL=0
while [ $# -gt 0 ]; do
    case "$1" in
        --source) SOURCE="$2"; shift 2 ;;
        --ref) REF="$2"; shift 2 ;;
        --modify-path) MODIFY_PATH=1; shift ;;
        --install-uv) INSTALL_UV=1; shift ;;
        --uninstall) UNINSTALL=1; shift ;;
        *) echo "unknown option $1 (see the header of install.sh)" >&2; exit 2 ;;
    esac
done

say() { printf '[tollgate] %s\n' "$*"; }
run() { say "run: $*"; "$@"; }

if [ -n "${TOLLGATE_HOME:-}" ]; then TG_HOME="$TOLLGATE_HOME"
elif [ "$(uname -s)" = "Darwin" ]; then TG_HOME="$HOME/Library/Application Support/Tollgate"
else TG_HOME="${XDG_DATA_HOME:-$HOME/.local/share}/tollgate"; fi
LOCAL_BIN="$HOME/.local/bin"
UV="$(command -v uv || true)"

if [ "$UNINSTALL" = 1 ]; then
    if [ -n "$UV" ]; then "$UV" tool uninstall tollgate || true; fi
    if [ -L "$LOCAL_BIN/tollgate" ] && [ -d "$TG_HOME/venv" ]; then rm -f "$LOCAL_BIN/tollgate"; say "removed $LOCAL_BIN/tollgate"; fi
    if [ -d "$TG_HOME/venv" ]; then rm -rf "$TG_HOME/venv"; say "removed $TG_HOME/venv"; fi
    say "kept your data: $TG_HOME (policy, audit log, accounts). Delete it with: rm -rf \"$TG_HOME\""
    say "if you ran 'tollgate service install --yes', run 'tollgate service uninstall --yes' first"
    exit 0
fi

if [ -e "$SOURCE" ]; then SOURCE="$(cd "$SOURCE" && pwd)"; fi  # local clone
SPEC="$SOURCE"
case "$SOURCE" in git+*) if [ -n "$REF" ]; then SPEC="$SOURCE@$REF"; fi ;; esac
say "installing tollgate from $SPEC"

if [ -z "$UV" ]; then
    PY=""
    for c in python3.13 python3 python; do
        if command -v "$c" >/dev/null 2>&1 && "$c" -c 'import sys; sys.exit(0 if sys.version_info >= (3, 13) else 1)' 2>/dev/null; then
            PY="$(command -v "$c")"; break
        fi
    done
    if [ -z "$PY" ]; then
        CMD="curl -LsSf https://astral.sh/uv/install.sh | sh"
        if [ "$INSTALL_UV" = 0 ]; then
            say "neither uv nor Python 3.13+ found. Install uv (it brings its own Python), then re-run this script:"
            echo "  $CMD"
            say "(or re-run with --install-uv to do it now)"
            exit 1
        fi
        if [ "$MODIFY_PATH" = 0 ]; then export UV_NO_MODIFY_PATH=1; fi
        say "run: $CMD"
        curl -LsSf https://astral.sh/uv/install.sh | sh
        UV="${UV_INSTALL_DIR:-$HOME/.local/bin}/uv"
        [ -x "$UV" ] || { echo "uv not found at $UV after its installer ran" >&2; exit 1; }
    fi
fi

if [ -n "$UV" ]; then
    run "$UV" tool install --force --reinstall --python 3.13 "$SPEC"
    BIN="$("$UV" tool dir --bin)"
    TOLLGATE="$BIN/tollgate"
else
    if [ ! -x "$TG_HOME/venv/bin/python" ]; then run "$PY" -m venv "$TG_HOME/venv"; fi
    run "$TG_HOME/venv/bin/python" -m pip install --upgrade --quiet "$SPEC"
    BIN="$LOCAL_BIN"
    mkdir -p "$BIN"
    ln -sf "$TG_HOME/venv/bin/tollgate" "$BIN/tollgate"
    TOLLGATE="$TG_HOME/venv/bin/tollgate"
fi
[ -x "$TOLLGATE" ] || { echo "installed, but $TOLLGATE is missing" >&2; exit 1; }
say "installed: $TOLLGATE"

case ":$PATH:" in
    *":$BIN:"*) ;;
    *)
        LINE="export PATH=\"$BIN:\$PATH\""
        if [ "$MODIFY_PATH" = 1 ]; then
            grep -qsF "$LINE" "$HOME/.profile" || printf '\n%s\n' "$LINE" >> "$HOME/.profile"
            say "added $BIN to PATH in ~/.profile (new login shells; zsh: also add it to ~/.zprofile)"
        else
            say "add to PATH yourself (or re-run with --modify-path):"
            echo "  $LINE"
        fi ;;
esac

run "$TOLLGATE" init

echo
say "done. tollgate = $TOLLGATE (the next steps above; 'tollgate doctor' checks the setup)"
say "upgrade: re-run this script. uninstall: sh install.sh --uninstall"
