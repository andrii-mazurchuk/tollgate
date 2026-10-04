# Publishing Tollgate to PyPI

**Published:** [`agent-tollgate` 1.0.0](https://pypi.org/project/agent-tollgate/) on 2026-10-04 (`uv tool install agent-tollgate`, then `tollgate init`). The demo still uses the GitHub one-liner. This is the runbook for the next release.

## Facts
- **Name:** `agent-tollgate`. `tollgate` is taken, and PyPI refused `tollgate-ai` as "too similar" to the existing `tollgateai` (it compares names with `-`, `_` and `.` removed). Before picking a name, check its run-together form too. The command stays `tollgate` (`[project.scripts]`).
- **Build:** `uv build --no-sources` gives a ~630 KB wheel + ~2.4 MB sdist. The wheel ships only the `tollgate` package: the UI, the mocks (`tollgate/mocks/`), the scenario (`tollgate/scenario.yaml`) and the packaged defaults (`tollgate/_defaults/`: policy, signatures, profiles).
- **Versions are permanent.** A version that is uploaded can be yanked but never re-uploaded. Bump `version` in `pyproject.toml` for every publish.

## One-time: account and token
1. Register at https://pypi.org/account/register/ and verify the email.
2. **2FA (required for uploads):** Account settings → *Two factor authentication* → authenticator app. Store the recovery codes.
3. **Token:** Account settings → *API tokens* → *Add API token*, scope **Project: agent-tollgate** (an account-wide token was only needed for the very first upload; revoke it).
4. The token (`pypi-…`) is shown once. **Never put it in a file in the repo, a file name, a commit, chat or a command line.** Paste it at a prompt (below), or keep it in a password manager.

## Each release
- Bump `version` in `pyproject.toml`, then `uv lock`.
- Full suite + `bash scripts/smoke.sh` green; commit and push.
- (Done once, 2026-10-04: the rename to `agent-tollgate`; both installers' `--uninstall` remove `agent-tollgate` and the older `tollgate` tool; `edge.version()` reads `agent-tollgate`.)

## Publish (PowerShell, from the repo root)
```powershell
Remove-Item -Recurse -Force dist -ErrorAction SilentlyContinue
uv build --no-sources
# check the wheel in a throwaway venv before uploading (never uninstall another dist from it: they share files):
uv venv $env:TEMP\tg-wheel; uv pip install --python $env:TEMP\tg-wheel\Scripts\python.exe (Get-Item .\dist\agent_tollgate-*.whl)
$env:TOLLGATE_HOME = "$env:TEMP\tg-wheel-home"; & $env:TEMP\tg-wheel\Scripts\tollgate.exe init; & $env:TEMP\tg-wheel\Scripts\tollgate.exe doctor; Remove-Item Env:TOLLGATE_HOME
$env:UV_PUBLISH_TOKEN = Read-Host "PyPI token"   # paste; never typed into a script
uv publish
Remove-Item Env:UV_PUBLISH_TOKEN
```
bash: `read -rs UV_PUBLISH_TOKEN && export UV_PUBLISH_TOKEN && uv publish && unset UV_PUBLISH_TOKEN`.

Optional dry run first on TestPyPI (separate account at https://test.pypi.org): `uv publish --publish-url https://test.pypi.org/legacy/`.

## After
- Check https://pypi.org/project/agent-tollgate/ and a clean install: `uv tool install --refresh agent-tollgate` → `tollgate init` → `tollgate doctor` (a new release can take a minute to reach the index).
- Later: replace tokens with **Trusted Publishing** (PyPI → project → Publishing → add GitHub publisher; a release workflow with `id-token: write` runs `uv publish` with no stored secret).

## If a token leaks
Revoke it at once (Account settings → API tokens), then make a new one. A token in a file name or a transcript counts as leaked.
