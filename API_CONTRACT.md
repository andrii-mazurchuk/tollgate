# API_CONTRACT.md

The boundary between **Track A (Gateway)** and **Track B (Content and evidence)**. Code: `tollgate/contract.py`.
Change both files together, in one commit on `main`, and tell the other session in the same turn.

## 1. `scan()` (B implements, A calls)

```python
from tollgate.content import scan
verdict = scan(text: str, point: ScanPoint, policy: dict) -> Verdict
```

- `point`: `"prompt" | "response" | "tool_args" | "tool_result"`.
- `policy`: the `content:` section of `policy.yaml`, already parsed by A's loader. B never reads the file itself, except `signatures.yaml`, whose path is given in `policy["signatures"]`.
- For `tool_args`, A passes `json.dumps(arguments)`. For `tool_result`, A passes the joined text content.
- `scan()` must be pure and safe to call on every request: no network and no exceptions. If it fails internally, it returns `block` with reason `content.scan_error` (fail closed). Text over `max_scan_chars` is scanned in chunks (reason `content.chunked`); over 2 MB it is blocked unscanned (`content.too_large`).
- Until B merges, the stub in `tollgate/content/__init__.py` returns `Verdict(action="allow")`.

`Verdict` example:
```json
{
  "action": "redact",
  "reasons": [{"rule": "pii.iban", "tier": 1, "detail": "IBAN, checksum valid", "span": [41, 73]}],
  "redacted_text": "Account: [IBAN:…2874]",
  "t2_score": null,
  "transforms": [],
  "latency_ms": {"t1": 0.8}
}
```

**How A applies a verdict:**

| Action | Tool arguments | Tool result / response |
|---|---|---|
| `allow` | forward | pass through |
| `redact` | forward `redacted_text` | return `redacted_text` |
| `block` | raise `ToolError` with the reasons | replace with an error |
| `approve` | wait for approval (helper; until then treat as `block`) | wait for approval (helper; until then treat as `block`) |

## 2. `AuditEvent` (A writes, B reads)

One JSON object per line, appended to `audit/events.jsonl`. It is the `dataclasses.asdict()` form of `AuditEvent`.

```json
{"ts": "2026-10-04T10:12:03.441Z", "role": "role-2", "key_id": "k_41c", "door": "tool",
 "verdict": "block", "scan_point": "tool_args", "source": "github", "tool": "github.pr.create",
 "reasons": [{"rule": "taint.flow", "tier": 0, "detail": "tainted by github.issues.read #12", "span": null}],
 "t2_score": null, "transforms": [], "latency_ms": {"role": 0.1, "taint": 0.1, "t1": 1.8},
 "tainted": true, "holds_private": true, "tokens": 0, "content_sha256": "c1e0…", "policy_version": "a3f9"}
```

Optional trace fields (absent in older lines; readers must default them):

```json
{"trace_id": "t_9f2c01ab", "session_id": "k_41c", "state_before": "untrusted+holds_private", "state_after": "untrusted+holds_private",
 "stages": [{"name": "key", "outcome": "ok", "detail": "", "ms": null}, {"name": "role", "outcome": "ok", "detail": "", "ms": 0.1},
            {"name": "arguments", "outcome": "ok", "detail": "", "ms": null}, {"name": "data_flow", "outcome": "fail", "detail": "taint.flow", "ms": 0.1},
            {"name": "content", "outcome": "skip", "detail": "", "ms": null}, {"name": "budget", "outcome": "skip", "detail": "", "ms": null},
            {"name": "approval", "outcome": "skip", "detail": "", "ms": null}]}
```

- `session_id` = `key_id` (a session is a role key). `state_*`: `clean` | `untrusted` | `holds_private` | `untrusted+holds_private`.
- `stages`: the check chain in order `key, role, arguments, data_flow, content, budget, approval`; `outcome` is `ok|warn|fail|skip`.
- Full text (original and masked args/results/prompts) goes only to the edge-local `audit/local_text.jsonl`, keyed by `trace_id`, capped to the last 2,000 calls.

Raw content is never written to `events.jsonl`. B's dashboard and eval read this file only.

## 3. `policy.yaml` ownership

| Section | Owner |
|---|---|
| `mode`, `servers`, `roles`, `labels`, `taint`, `budget`, `loops`, `models` | A |
| `content` (and `signatures.yaml`) | B |

A's loader validates only its own sections and passes `content` through untouched.

## Changelog
| When | Change |
|---|---|
| 2026-10-03 16:40 | Initial contract |
| 2026-10-03 22:10 | `AuditEvent` gains optional `trace_id`, `session_id`, `stages`, `state_before`, `state_after` (edge UI); full text lives only in edge-local `audit/local_text.jsonl` |
