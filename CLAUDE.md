# CLAUDE.md

Tollgate is a HackYeah 2026 project (Goldman Sachs, "AI Control Layer"). One operator drives **two Claude sessions**, one per track. The deadline is **Sun 2026-10-04 11:00**. Clock and gates are in `docs/process/PLAN.md`.

Read in this order before working: `docs/process/PLAN.md` (what is next, for which track), `docs/process/API_CONTRACT.md` (the boundary), `TOLLGATE.md` (spec and AC1–AC16). The product page is `README.md`; background is in `docs/research.md`.

## Pitch
Every role gets its own MCP server, generated from one policy file, that exposes exactly the tools that role may use. Every tool call is checked locally for malicious content. Once a session has read untrusted content, the server blocks the private → public data flow.

## Which track am I?
| Worktree | Track | Owns | Branches |
|---|---|---|---|
| `rebel/` | **A: Gateway** | `tollgate/gateway/`, `mocks/`, `tollgate/cli.py` | `a/<feature>` |
| `rebel-b/` | **B: Content and evidence** | `tollgate/content/`, `tollgate/eval/`, `tests/corpus/`, `signatures.yaml` | `b/<feature>` |

**Never edit the other track's folders.** Shared files are `tollgate/contract.py`, `docs/process/API_CONTRACT.md`, `docs/process/PLAN.md`, `policy.yaml` (per the section ownership in the contract) and `tests/test_smoke.py`. Change them only on `main`, in small commits, and say so in your reply so the operator can tell the other session.

## Stack
- Python 3.13, **uv** (never pip directly). bun/bunx for any JS (never npm/npx).
- **fastmcp==4.0.10, pinned.** It uses `httpx2`, not `httpx`.
- pytest + pytest-asyncio (`asyncio_mode=auto`).
- onnxruntime (tier 2), Ollama optional (model door); the `/console` and `/edge` UIs are plain JS in `tollgate/ui/`.

## Run
```
uv sync
uv run pytest -q              # full suite; unbuilt ACs show as xfail
bash scripts/smoke.sh         # demo path; must pass before every merge to main
uv run tollgate test          # suite entry point judges use
```

## TDD loop
1. The step's AC test is red (strict `xfail`).
2. Build until it passes, then remove the marker.
3. Run smoke + full suite.
4. Merge to `main`.

Unit tests only for validators and taint logic. Small commits; `main` is never broken.

## fastmcp gotchas (verified in research)
- The middleware parameter must be named exactly `call_next`.
- Filtering `on_list_tools` does **not** block calls. Deny again in `on_call_tool`.
- Read the key with `get_http_headers(include={"authorization"})`, because Authorization is stripped by default.
- Mounted `http_app(path="/")` sub-apps need their lifespans entered manually (AsyncExitStack) and trailing-slash URLs (`/mcp/role-1/`).
- MCP session IDs are not stable. **Taint is keyed by role key.**
- Tests: in-memory `Client(server)`. For header tests, use `StreamableHttpTransport` with `httpx2.ASGITransport(app)` inside `app.router.lifespan_context(app)`.

## Conventions
- Anything outside the current step goes to "Later" in `docs/process/PLAN.md`, not into code.
- Secrets go in `.env` (gitignored); keys are documented in `.env.example`.
- Reply to the operator tersely: what changed, test status, what is next.
