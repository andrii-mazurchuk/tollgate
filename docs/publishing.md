# Publishing Tollgate to PyPI

Not published yet (decided 2026-10-04: the demo and README use the GitHub one-liner). This is the runbook for when we do.

## Facts
- **Name:** `tollgate` is taken on PyPI; `tollgate-ai` is free (checked 2026-10-04). The command stays `tollgate` (`[project.scripts]`).
- **Build:** `uv build --no-sources` gives a ~640 KB wheel + ~3 MB sdist. The wheel already ships the UI and the packaged defaults (`tollgate/_defaults/`: policy, signatures, profiles, scenario).
- **Versions are permanent.** A version that is uploaded can be yanked but never re-uploaded. Bump `version` in `pyproject.toml` for every publish.

## One-time: account and token
1. Register at https://pypi.org/account/register/ and verify the email.
2. **2FA (required for uploads):** Account settings → *Two factor authentication* → authenticator app. Store the recovery codes.
3. **Token:** Account settings → *API tokens* → *Add API token*. The first upload needs scope **Entire account** (the project does not exist yet). After it, replace that token with one scoped to `tollgate-ai` and revoke the account-wide one.
4. The token (`pypi-…`) is shown once. **Never put it in a file in the repo, a file name, a commit, chat or a command line.** Paste it at a prompt (below), or keep it in a password manager.

## Before the first publish (code changes)
- `pyproject.toml`: `name = "tollgate-ai"`, then `uv lock`.
- `install.ps1` / `install.sh`: the uninstall line uses the tool name: `uv tool uninstall tollgate` → `tollgate-ai`. A machine that already has the old `tollgate` tool: `uv tool uninstall tollgate` once.
- Move `mocks/` under `tollgate/` (or drop it from `[tool.hatch.build.targets.wheel] packages`), so the wheel does not install a top-level `mocks` module into users' environments.
- README Install: add `uv tool install tollgate-ai` (and `uvx --from tollgate-ai tollgate doctor`).
- Full suite + `bash scripts/smoke.sh` green; commit.

## Publish (PowerShell, from the repo root)
```powershell
Remove-Item -Recurse -Force dist -ErrorAction SilentlyContinue
uv build --no-sources
# check the wheel in an isolated tool env before uploading:
uv tool install --force .\dist\tollgate_ai-*.whl; tollgate doctor
$env:UV_PUBLISH_TOKEN = Read-Host "PyPI token"   # paste; never typed into a script
uv publish
Remove-Item Env:UV_PUBLISH_TOKEN
```
bash: `read -rs UV_PUBLISH_TOKEN && export UV_PUBLISH_TOKEN && uv publish && unset UV_PUBLISH_TOKEN`.

Optional dry run first on TestPyPI (separate account at https://test.pypi.org): `uv publish --publish-url https://test.pypi.org/legacy/`.

## After
- Check https://pypi.org/project/tollgate-ai/ and a clean install: `uv tool install tollgate-ai` → `tollgate doctor`.
- Swap the account-wide token for a project-scoped one (step 3).
- Later: replace tokens with **Trusted Publishing** (PyPI → project → Publishing → add GitHub publisher; a release workflow with `id-token: write` runs `uv publish` with no stored secret).

## If a token leaks
Revoke it at once (Account settings → API tokens), then make a new one. A leaked token in a file name or a transcript counts as leaked.
