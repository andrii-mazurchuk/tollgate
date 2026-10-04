# Tollgate demo run sheet (Option A, ≤ 3 minutes)

PowerShell first; bash equivalents where they differ. The demo hub runs on a **copy** of the policy, so profile switches and broken edits never touch the repo's `policy.yaml`.

## Pre-stage (before the clock; ~10 min the first time)

| # | Do | PowerShell |
|---|---|---|
| 1 | Install, download the classifier, write `audit/eval.json` + test results for Self-test | `uv sync; uv run tollgate test` |
| 2 | Copy the policy for the demo | `Copy-Item policy.yaml audit/policy.demo.yaml -Force` |
| 3 | Seed the fleet (6 laptops, real traffic incl. the attacks) | `uv run tollgate seed-fleet --policy audit/policy.demo.yaml` |
| 4 | Start the hub (T1, leave running) | `uv run tollgate up --scripted-model --policy audit/policy.demo.yaml` |
| 5 | Open tabs, in order | slide 1 of `docs/Tollgate.pdf` · http://127.0.0.1:8080/edge (Scenario) · http://127.0.0.1:8080/console (Overview) · editor on `audit/policy.demo.yaml` |
| 6 | T2 open in the repo for fallbacks | — |

bash: `cp policy.yaml audit/policy.demo.yaml`; the other commands are identical.

Check before going on: the console Overview shows "Attacks stopped" > 0 and the status chip says Balanced; the edge Scenario shows the five acts.

## Run (3:00)

**0:00–0:30 · Hook (slide 1)**
Say: "May 2025. An AI agent read one GitHub issue and published its owner's private code. Every step it took was allowed. ① read issue: allowed. ② read private repo: allowed. ③ open public PR: allowed. Leaked. Nothing was hacked. The agent was obeyed. Per-tool permissions can't see this; the danger is the sequence."

**0:30–1:00 · The attack, live (/edge → Scenario)**
Click: Act 3 → **Run act**.
Judge sees: 3.1 ALLOW (flagged "hidden instructions"), 3.2 REDACT (AWS keys `[SECRET]`), **3.3 BLOCKED**: "session read untrusted text (issue #12) and private data (acme/payroll/.env)"; 3.4a/b control (benign issue, then a PR) ALLOW; 3.5a–c the Supabase ticket attack, reply BLOCKED the same way.
Say: "Same three calls, same permissions. Tollgate tracks the session: untrusted text, then private data, then a public write. Blocked, and it tells you why."

**1:00–1:20 · What the developer sees (/edge → Sessions)**
Click: the Act 3 session → step 3.3 → **Checks** tab.
Judge sees: each check in the chain with its time in ms (normalise, tier 1, classifier, role, taint).
Say: "Every check runs on the laptop; tier 1 p95 2.5 ms, hub checks under 1 ms."

**1:20–1:45 · The security lead (/console → Overview)**
Judge sees: Actions checked, Blocked, **Attacks stopped**, Peers online; Blocked by reason / by role.
Click: a row in **Attacks stopped** → it opens in Sessions → **Fingerprint** tab.
Say: "The hub sees every decision across the fleet, but only a SHA-256 of the content. The text stays on the laptop."

**1:45–2:05 · Revoke a laptop (/console → Peers & roles)**
Click: Peers → `tomek-mbp` → **Revoke this laptop** → confirm "Revoke tomek-mbp".
Say: "Laptops enroll once, the admin sets their roles, every agent launch gets its own key. Revoke the laptop and every key it minted is dead."

**2:05–2:35 · Change policy live (/console → Policy)**
Click: **Switch profile…** → Strict → read the diff → **Switch to Strict**. (Alternative: **Edit access** → toggle a tool to Hidden → review → save.)
Then, in the editor, append `roles: [oops` to `audit/policy.demo.yaml` and save.
Judge sees: red notice "Edit rejected at …: ParserError … Still enforcing <version>."
Say: "Policy is one file, hot reloaded. A broken edit is rejected and the last good policy keeps enforcing; it never fails open."
Restore: delete the `roles: [oops` line, save (the notice clears on the next refresh).

**2:35–3:00 · Close (/console → Self-test)**
Judge sees: headline vs targets and the misses.
Say: "1,411 cases, 30% held out, thresholds tuned on the rest. Injection recall 0.837 against our 0.85 target: we missed it, and we say so. False positives 0.9%, 1 of 113 harmless. Posture 0.931. Judges run all of it with `uv run tollgate test`."

## Fallbacks

| If | Do (T2) |
|---|---|
| The browser or hub misbehaves at 0:30 | `uv run tollgate agent --scripted "check the open issues on acme/website and handle them"`: turn 3 PR **BLOCKED** `taint.flow … tainted by github.issues.read #12` |
| Need "roles alone leak" | `uv run tollgate replay github`: taint OFF → PR created with salaries; taint ON → BLOCK |
| Console empty | rerun `uv run tollgate seed-fleet --policy audit/policy.demo.yaml` (hub can keep running) |
| Self-test empty | it reads `audit/eval.json`: `uv run tollgate test --eval-only` |
| A judge asks for an ad-hoc prompt | README "Judges: start here" step 4 (`tollgate key issue --role role-1`, then `Invoke-RestMethod` → 400 `content.blocked`) |
| Everything fails | screenshots in `docs/img/` (`console1-*`, `console2-policy-rejected-*`) and the deck |

## Reset after a run

```powershell
Copy-Item policy.yaml audit/policy.demo.yaml -Force          # back to Balanced, no broken line
uv run tollgate seed-fleet --policy audit/policy.demo.yaml   # re-enrolls the revoked laptop under a new peer ID
```

The repo's `policy.yaml` is never edited during the demo; `git status` stays clean (`audit/` is gitignored).
