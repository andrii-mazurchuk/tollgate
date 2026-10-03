"""`tollgate perf` (AC15): in-process calls through the role-2 gateway; per-stage p50/p95 from the audit
events' latency_ms, plus wall-clock overhead vs calling the mock directly. Tier 2 is switched off here (it is
gated and measured per text length by the eval, audit/eval.json), so these numbers are the Hub + tier 1 path."""
import asyncio
import copy
import json
import os
import statistics
import tempfile
import time
from pathlib import Path

from fastmcp import Client
from fastmcp.exceptions import ToolError

from tollgate.gateway import build_role_server, taint
from tollgate.gateway.policy import PolicyHolder, load_policy

ROOT = Path(__file__).resolve().parents[2]
TARGET_MS = {"hub": 5.0, "t1": 5.0, "t2_short": 80.0}  # AC15 p95 targets
IBAN = "PL61 1090 1014 0000 0712 1981 2874"


def pct(xs: list[float]) -> dict:
    if not xs:
        return {"n": 0, "p50": None, "p95": None}
    q = statistics.quantiles(xs, n=100) if len(xs) > 1 else [xs[0]] * 99
    return {"n": len(xs), "p50": round(q[49], 3), "p95": round(q[94], 3)}


def calls(i: int) -> list[tuple[str, str, dict]]:
    """One round: (kind, tool, args). Args vary with i so the loop cut-off never fires."""
    return [
        ("allowed", "tickets.read", {"id": 1 + i % 2}),
        ("denied", "files.fs.delete", {"path": f"/workspace/tmp{i}.txt"}),  # not in role-2's exact tool list
        ("taint", "github.pr.create", {"repo": "acme/website", "title": f"t{i}", "body": "b"}),  # tainted session
        ("content", "files.fs.write", {"path": f"/workspace/refund{i}.txt",  # args redacted (IBAN, email)
                                       "content": f"Refund #{i} to {IBAN}, confirm to jan@acme.pl"}),
    ]


async def _run(policy: PolicyHolder, n: int) -> tuple[dict, list[float]]:
    from mocks import tickets

    srv = build_role_server("role-2", policy)
    wall: dict[str, list[float]] = {}
    direct: list[float] = []
    async with Client(srv) as gw, Client(tickets.mcp) as raw:
        taint.reset("local")
        await gw.call_tool("github.issues.read", {"repo": "acme/website", "number": 12})  # taint the session ...
        await gw.call_tool("github.repo.read", {"repo": "acme/payroll", "path": "README.md"})  # ... and hold private
        for i in range(n):
            for kind, tool, args in calls(i):
                t0 = time.perf_counter()
                try:
                    await gw.call_tool(tool, args)
                except ToolError:
                    pass
                wall.setdefault(kind, []).append((time.perf_counter() - t0) * 1000)
            t0 = time.perf_counter()
            await raw.call_tool("read", {"id": 1 + i % 2})
            direct.append((time.perf_counter() - t0) * 1000)
    taint.reset("local")
    return wall, direct


def measure(n: int = 200, policy: PolicyHolder | None = None) -> dict:
    data = copy.deepcopy((policy or load_policy()).data)
    (data.get("content") or {}).pop("injection", None)  # tier 2 off: see module docstring
    old = os.environ.get("TOLLGATE_AUDIT")
    with tempfile.TemporaryDirectory() as d:
        os.environ["TOLLGATE_AUDIT"] = log = str(Path(d) / "perf.jsonl")
        try:
            wall, direct = asyncio.run(_run(PolicyHolder(data), n))
            events = [json.loads(line) for line in Path(log).read_text(encoding="utf-8").splitlines()]
        finally:
            if old is None:
                os.environ.pop("TOLLGATE_AUDIT", None)
            else:
                os.environ["TOLLGATE_AUDIT"] = old
    lat = [e["latency_ms"] for e in events[2:]]  # skip the two set-up calls
    stages = {s: pct([x[s] for x in lat if s in x]) for s in ("role", "taint", "t1")}
    stages["hub"] = pct([x.get("role", 0) + x.get("taint", 0) for x in lat if "role" in x])
    res = {
        "n_rounds": n,
        "note": "in-process, role-2, tier 2 off; hub = role + taint checks; t1 summed over tool_args + tool_result scans",
        "stages_ms": stages,
        "wall_ms": {k: pct(v) for k, v in wall.items()},
        "direct_mock_ms": pct(direct),
    }
    a, dm = res["wall_ms"]["allowed"], res["direct_mock_ms"]
    res["overhead_ms"] = {"p50": round(a["p50"] - dm["p50"], 3), "p95": round(a["p95"] - dm["p95"], 3)}
    ev = ROOT / "audit" / "eval.json"
    if ev.exists():
        t2 = json.loads(ev.read_text(encoding="utf-8")).get("tier2") or {}
        res["tier2_from_eval"] = {k: t2.get(k) for k in ("sync_share", "latency_ms", "latency_ms_short")}
    got = {"hub": stages["hub"]["p95"], "t1": stages["t1"]["p95"],
           "t2_short": ((res.get("tier2_from_eval") or {}).get("latency_ms_short") or {}).get("p95")}
    res["ac15"] = {k: {"p95": v, "target": TARGET_MS[k], "met": None if v is None else v < TARGET_MS[k]}
                   for k, v in got.items()}
    return res


def report(res: dict) -> str:
    def row(name, p):
        return f"  {name:<22} p50 {p['p50']:>8} ms   p95 {p['p95']:>8} ms   (n={p['n']})"

    out = [f"== tollgate perf: {res['n_rounds']} rounds, {res['note']} =="]
    out += ["stages (from audit latency_ms):"] + [row(k, v) for k, v in res["stages_ms"].items()]
    out += ["wall clock per call through the gateway:"] + [row(k, v) for k, v in res["wall_ms"].items()]
    out += [row("direct mock call", res["direct_mock_ms"]),
            f"  gateway overhead (allowed - direct): p50 {res['overhead_ms']['p50']} ms, p95 {res['overhead_ms']['p95']} ms"]
    t2 = res.get("tier2_from_eval")
    if t2:
        out.append(f"tier 2 (audit/eval.json, model ms): all sync p50 {t2['latency_ms']['p50']} p95 {t2['latency_ms']['p95']}; "
                   f"short (<=64 tok) p50 {t2['latency_ms_short']['p50']} p95 {t2['latency_ms_short']['p95']}; "
                   f"sync share {t2['sync_share']}")
    else:
        out.append("tier 2: audit/eval.json missing; run `tollgate test --eval-only`")
    out.append("AC15: " + "; ".join(f"{k} p95 {v['p95']} < {v['target']} ms: "
                                    f"{'n/a' if v['met'] is None else 'MET' if v['met'] else 'GAP'}" for k, v in res["ac15"].items()))
    return "\n".join(out)


def main(n: int = 200, out: Path = ROOT / "audit" / "perf.json") -> int:
    res = measure(n)
    print(report(res))
    out.parent.mkdir(exist_ok=True)
    out.write_text(json.dumps(res, indent=1), encoding="utf-8")
    print(f"written {out.relative_to(ROOT) if out.is_relative_to(ROOT) else out}")
    return 0
