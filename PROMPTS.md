# PROMPTS.md

Paste-ready prompts for one operator driving two Claude sessions. The prompts point at files and never embed the plan, so the plan can change without them going stale.

## 0. One-time setup (once, from `rebel/` on main)
```
git worktree add ../rebel-b -b b/tier1
cd ../rebel-b && uv sync
```
Open session 1 in `rebel/` (Track A) and session 2 in `rebel-b/` (Track B).

## 1. Start of a work block (each session)
```
Read CLAUDE.md, PLAN.md and API_CONTRACT.md. I am Track [A|B]. It is [hh:mm].
Take the next step for my track from the PLAN.md schedule. Its AC test is the target: confirm it is red, then build to green test-first and remove the xfail marker.
Branch [a|b]/<feature>. Stay inside my track's folders. If you are behind the clock, say which cut from PLAN.md applies.
```

## 2. Before merge to main (each session)
```
Run bash scripts/smoke.sh and uv run pytest -q. If both pass: merge my branch into main, push, and tell me in one line what landed and which AC turned green. If either fails: fix it and do not merge.
```

## 3. Pull the other track's work (each session, after the other merges)
```
Merge main into my branch, run the full suite, and report anything the other track's merge broke on my side. Fix only my side.
```

## 4. Contract change (whichever session needs it)
```
I need this change to the A/B boundary: [change]. Update tollgate/contract.py and API_CONTRACT.md together on main, add a changelog line, run the suite, and give me a one-paragraph note to paste into the other session.
```

## 5. Milestone gate (Track A session, at 17:40 / 23:00 / 10:00)
```
Read PLAN.md "Gates". On a clean checkout of main run smoke and the full suite. For each AC due at this gate report pass, fail or xfail with evidence. Propose: fix now, or cut per PLAN.md. If the gate passes, tag it ([m0|submission-1|final]) and push the tag.
```

## 6. Docs snapshot for submission 1 (Track B session, 22:00)
```
Update README.md so every command it shows works today, and mark planned ones as planned. Add a "Status at submission 1" section to TOLLGATE.md listing which ACs are green. Draft the HackTribe description (title, team, ≤150 words). Don't touch code.
```

## 7. Final deliverables (Track B session, ~04:40)
```
Write DEMO.md (a 3-minute script from TOLLGATE.md §9: what to run, what to say, a fallback per step) and a 10-slide outline (problem, gap, product, architecture diagram, taint demo, content tiers + numbers, policy live edit, test suite results, dashboard, team). Use real numbers from `tollgate test`.
```
