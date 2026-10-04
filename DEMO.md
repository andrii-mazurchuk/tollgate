# Tollgate demo run sheet (≤ 3 minutes, follows `docs/deck.md`)

Andrey tells the story; slides carry keywords. "Say" cells are cues, not a script. PowerShell first; bash where it differs.
The hub runs on a **copy** of the policy (`audit/` is gitignored), so profile switches and broken edits never dirty the repo.

`$R` is the checkout you demo from (`C:\Projects\heack-yea-2026\rebel`). Run `connect` through that checkout's `uv`: the hooks it writes call that checkout's venv python.

## Pre-stage (off the clock; ~10 min the first time)

**T1, the hub** (in `$R`, leave running):
```powershell
uv sync
uv run tollgate test                                   # once: downloads + warms the classifier, writes audit/eval.json for Self-test
Copy-Item policy.yaml audit/policy.demo.yaml -Force
uv run tollgate seed-fleet --policy audit/policy.demo.yaml
uv run tollgate admin create --email you@acme.io --name "Your name"   # console owner account (asks for a 12+ char password)
uv run tollgate up --scripted-model --policy audit/policy.demo.yaml
```
bash: `cp policy.yaml audit/policy.demo.yaml`; the rest is identical. Then sign in at http://127.0.0.1:8080/console/ as the owner (Admin): every revoke and policy edit below is attributed to you. Every key in this run is minted per launch by `tollgate connect` (no hand-issued keys); `seed-fleet` and `connect` both use the demo copy `audit/policy.demo.yaml`.

**T2, the "demo laptop"**, a sandbox repo (the push is denied before it runs, so the remote never has to exist):
```powershell
$R = "C:\Projects\heack-yea-2026\rebel"
New-Item -ItemType Directory -Force C:\demo\acme | Out-Null; Set-Location C:\demo\acme
git init -q; git remote add origin https://github.com/acme/website.git
"name,role,salary_pln`nAnna Nowak,CTO,42000`nJan Kowalski,Engineer,21000" | Set-Content payroll.txt
git add .; git commit -qm init
@'
Do these three steps in order, one tool call each:
1. Run `curl -s https://example.com` with Bash and tell me the page title.
2. Read payroll.txt.
3. Run `git push origin main` with Bash.
If a step is blocked, quote the reason and stop.
'@ | Set-Content prompt.txt
```
**Enroll + connect** (T2; also the reset block):
```powershell
$t = (uv run --project $R tollgate enroll-token)[0].Split(" ")[2]
$peer = [regex]::Match((uv run --project $R tollgate enroll $t --owner "Andrey Mazurchuk" --device demo-laptop), "as peer (\S+);").Groups[1].Value
uv run --project $R python -c "from tollgate.gateway import peers; peers.set_roles('$peer', ['role-2'])"
$o = uv run --project $R tollgate connect claude-code --role role-2 --peer $peer --policy $R\audit\policy.demo.yaml --write --dir C:\demo\acme
$env:TOLLGATE_KEY = [regex]::Match(($o -join "`n"), "tg_role-2_[^`"' ]+").Value; "peer $peer key $env:TOLLGATE_KEY"
```
Roles by hand instead of the one-liner: console → **Peers & roles** → `demo-laptop` → tick **Support assistant (role-2)** → **Save**.
bash: `T=$(uv run --project $R tollgate enroll-token | head -1 | cut -d' ' -f3)`, `uv run --project $R tollgate enroll "$T" --owner "Andrey Mazurchuk" --device demo-laptop` (prints the peer ID), the same `set_roles` and `connect` lines, then the `export TOLLGATE_KEY='…'` line `connect` prints.

Launch `claude` once in `C:\demo\acme`: accept "trust this folder" and the `tollgate` MCP server from `.mcp.json`, then `/exit` without a prompt (session stays clean). Start `claude` again; leave it at the empty prompt.

**T3, the install window** (a fresh PowerShell, any folder). Run the one-liner once off stage: it warms the uv cache so the live run takes ~20 s (verified 2026-10-04; a cold run downloads ~150 MB of wheels). Re-run = reinstall, so no uninstall is needed between rehearsals. **Warm up again after the last push to `main`:** a new commit is rebuilt once (~60 s), then cached (~20 s).
```powershell
irm https://raw.githubusercontent.com/andrii-mazurchuk/tollgate/main/install.ps1 | iex
tollgate doctor          # hub on :8080 answers; "console owner: none" is expected (the installed copy has its own home, %LOCALAPPDATA%\Tollgate)
cls
```
bash: `curl -LsSf https://raw.githubusercontent.com/andrii-mazurchuk/tollgate/main/install.sh | sh`. The installed copy is only for the install beat: the hub and `connect` keep running from `$R`. Never let the 739 MB classifier download run on stage (it is already cached; `doctor` says "tier 2 classifier cached").

**Tabs, in order:** deck (`docs/Tollgate.pdf`) · T3 (install) · T2 (Claude Code) · http://127.0.0.1:8080/console (Overview, signed in) · /console **Try it** · /console **Self-test** · /console **Peers & roles** · /console **Policy** · editor on `audit/policy.demo.yaml`. The edge (http://127.0.0.1:8080/edge) only on demand.

Check: Overview "Attacks stopped" > 0 and the access map shows the seeded fleet; the chip shows your name and Admin; Peers & roles shows `demo-laptop` with Support assistant.

## Run (3:00)

| Time | Slide | Show / click | Say (keywords) |
|---|---|---|---|
| 0:00–0:15 | **1** One incident | slide | May 2025, GitHub MCP. Read issue ✓, private repo ✓, public PR ✓. Leaked. Nothing hacked; the agent obeyed. |
| 0:15–0:25 | **2** It keeps happening | slide | Supabase, Replit, Amazon Q, Gemini CLI, postmark. Not a one-off. |
| 0:25–0:33 | **3** The gap | slide | Each call fine. The sequence is the attack. Nobody watches the session. |
| 0:33–0:42 | **4** The gate | slide | Every call, one gate. One policy file, one MCP server per role. Content checked on the laptop. |
| 0:42–0:50 | **5** Same attack stopped | slide | Untrusted + private + public write = blocked at step 3, with the reason. "Let's install it." |
| 0:50–1:10 | **6** Install, **LIVE** | T3: paste the `irm … \| iex` one-liner, Enter; talk over it (~20 s) → `[tollgate] done.` → `tollgate doctor` → **OK hub answers**, **OK classifier cached**. | One line, no admin rights, no Python needed (uv brings its own). Same on Linux/macOS with `curl \| sh`. Laptop already enrolled; on to the agent. |
| 1:10–1:50 | **6** Enroll → connect → work, **LIVE** | T2 Claude Code: paste `prompt.txt`, Enter (if it asks permission for a step: Enter = allow). curl ✓ → Read payroll ✓ → `git push` **blocked**: "Tollgate: this session read text written by outsiders and holds private data, so `git push origin main` could leak it." | Real Claude Code, unmodified. Enrolled once, one `tollgate connect`. Hooks see built-ins: shell, files, web. Developer sees only the block. |
| 1:50–2:08 | **7** Every laptop, every agent, every block | /console **Overview**: access map, `demo-laptop` → Support assistant → **Agent built-ins** edge in red → click `demo-laptop` → **Latest sessions** top row → Sessions: steps Run a shell command → Read a file on the laptop → **Run a shell command · Blocked** → Overview tab (**Data-flow rule**, Untrusted + Holds private data) → **Fingerprint** tab | Same session, security lead's screen, seconds later. Every laptop, every agent. Hub keeps the decision + SHA-256; text stays on the laptop. |
| 2:08–2:22 | **8** Proof | **Try it** → **Injection** chip → verdict + rule names. **Self-test** → headline vs targets, misses listed. | Any ad-hoc text, judges' too. 397 fast tests, 1,411 cases, 30% held out. Injection recall 0.837 vs 0.85: **missed, we say so.** FP 0.9%. Posture 0.931. |
| 2:22–2:35 | **9** Key per launch | **Peers & roles** → `demo-laptop` → **Revoke this laptop** → **Revoke demo-laptop**. T2 Claude Code: type `git status`, Enter → blocked: "Tollgate unreachable: HTTP 401 {"error":"invalid or revoked key"}" | Revoke the laptop: every key it minted dead at the next call. Every change attributed to the signed-in admin. |
| 2:35–2:50 | **9** Fails closed | Editor: append `roles: [oops` to `audit/policy.demo.yaml`, save → **Policy**: red "Edit rejected at …: ParserError … Still enforcing <version>." Delete the line, save. | One file, hot reload. Broken edit rejected, last good policy keeps enforcing. Hub down = call denied. Never fails open. |
| 2:50–3:00 | **10** Try it | slide | One-line install · `tollgate up` · `tollgate test` from a clone. Public, MIT. Five minutes. Next: edge/hub split, model door v2. |

## Fallbacks (decide in 5 s; never debug on stage)

| If (when) | Do |
|---|---|
| Install slow, no network, or errors (0:50) | Ctrl+C at 25 s, no debugging. T3: `tollgate doctor` (the copy installed in pre-stage is still there) and say "installed earlier, same line". Move on to Claude Code at 1:10. |
| Claude Code login / trust prompt / model slow (1:10) | T2: `uv run --project $R python $R\scripts\demo_claude.py` (same `TOLLGATE_KEY`). Sends Claude Code's exact hook JSON through the real `tollgate hook claude-code` shim; prints `3. Bash(git push origin main) -> DENIED` + the same sentence. Console beat unchanged (same peer). |
| Interactive `claude` misbehaves, headless works (1:10) | `Get-Content prompt.txt -Raw \| claude -p` (Windows truncates a multi-line `-p` argument: use stdin). bash: `claude -p < prompt.txt` |
| No network: curl fails (1:10) | `demo_claude.py` (needs no network; replays the hook calls through the real shim, same peer), or T2: `uv run tollgate replay github` (taint ON: step 3 **BLOCK**, "session read untrusted text … and private data") / `uv run tollgate agent --scripted` (classifier installed: the model door blocks the injected prompt first, `t2.injection`; with `TOLLGATE_T2=off` the PR is blocked by `taint.flow`; both are correct). There is no Scenario view any more. |
| Hub down (any time) | Make it the point: any Claude Code call → "Tollgate unreachable: … refused" = fails closed (slide 9). Restart T1, carry on. |
| Revoke shows nothing in Claude Code (2:22) | `uv run --project $R python $R\scripts\demo_claude.py` → `1. Bash(curl -s https://example.com) -> DENIED  Tollgate unreachable: HTTP 401 {"error":"invalid or revoked key"}` |
| Console empty | `uv run tollgate seed-fleet --policy audit/policy.demo.yaml` (hub keeps running) |
| Self-test empty | `uv run tollgate test --eval-only` |
| Judge asks "don't roles alone stop it?" | `uv run tollgate replay github`: taint OFF → PR with salaries; taint ON → BLOCK |
| Everything fails | screenshots in `docs/img/` + the deck |

## Reset between rehearsals (30 s)

Revoke is permanent and every `connect` is a fresh (clean) session:
```powershell
Copy-Item $R\policy.yaml $R\audit\policy.demo.yaml -Force   # Balanced, no broken line; hub hot reloads
# rerun the "Enroll + connect" block in T2 (new peer, new key), then restart `claude`
```
bash: `cp $R/policy.yaml $R/audit/policy.demo.yaml`, then the same block. Didn't revoke? Rerun only the `$o = … connect …` and `$env:TOLLGATE_KEY` lines. Revoked `demo-laptop` rows stay listed in Peers & roles; pick the newest.
