"""Shared types between Track A (gateway) and Track B (content). Pinned by API_CONTRACT.md.

Change this file only together with API_CONTRACT.md, in its own commit on main.
"""
from dataclasses import dataclass, field
from typing import Literal

Action = Literal["allow", "redact", "approve", "block"]
ScanPoint = Literal["prompt", "response", "tool_args", "tool_result"]

# most severe wins when fusing findings
SEVERITY: dict[str, int] = {"allow": 0, "redact": 1, "approve": 2, "block": 3}


@dataclass
class Reason:
    rule: str                         # e.g. "pii.iban", "taint.flow", "role.denied"
    tier: int                         # 0 = policy/role/taint, 1 = regex, 2 = classifier, 3 = judge
    detail: str = ""                  # human-readable cause, shown on the dashboard
    span: tuple[int, int] | None = None


@dataclass
class Verdict:
    action: Action
    reasons: list[Reason] = field(default_factory=list)
    redacted_text: str | None = None  # set when action == "redact"
    t2_score: float | None = None     # classifier score, None if tier 2 did not run
    transforms: list[str] = field(default_factory=list)   # normalisation steps that fired
    latency_ms: dict[str, float] = field(default_factory=dict)  # per tier: {"t1": 1.2, "t2": 31.0}


@dataclass
class AuditEvent:
    ts: str                           # ISO 8601 UTC
    role: str
    key_id: str
    door: Literal["tool", "model"]
    verdict: Action
    reasons: list[Reason] = field(default_factory=list)
    scan_point: ScanPoint | None = None
    source: str | None = None         # source MCP server, e.g. "github"
    tool: str | None = None           # namespaced tool, e.g. "github.pr.create"
    t2_score: float | None = None
    transforms: list[str] = field(default_factory=list)
    latency_ms: dict[str, float] = field(default_factory=dict)
    tainted: bool = False
    holds_private: bool = False
    tokens: int = 0
    content_sha256: str | None = None
    policy_version: str | None = None
    # optional per-call trace (2026-10-03 edge UI); old readers ignore them
    trace_id: str | None = None       # one per decision; keys audit/local_text.jsonl (edge-only full text)
    session_id: str | None = None     # = key_id (taint is keyed by key)
    stages: list[dict] = field(default_factory=list)  # [{name, outcome: ok|warn|fail|skip, detail, ms}], see STAGES
    state_before: str | None = None   # SessionState
    state_after: str | None = None


# check chain order; key|role|arguments|data_flow|content|budget|approval
STAGES = ("key", "role", "arguments", "data_flow", "content", "budget", "approval")
# "clean" | "untrusted" | "holds_private" | "untrusted+holds_private"
SessionState = str
