"""Offline evaluation: scan() over tests/corpus, per-source confusion matrix, latency, posture score (TOLLGATE §6)."""
import json
import statistics
from collections import defaultdict
from pathlib import Path

from tollgate.content import scan
from tollgate.eval.corpus import CORPUS, load

WEIGHTS = {"pii": 3, "secrets": 3, "injection": 3, "signatures": 1, "obfuscation": 1}
ROOT = CORPUS.parents[1]


def detected(v) -> bool:
    return v.action != "allow" or any(r.rule.startswith(("inj.", "sig.")) for r in v.reasons)


def _enabled(content: dict, control: str) -> bool:
    # missing key = tier 1 defaults apply = on; explicit false/off disables the control
    return content.get(control, True) not in (False, None, "off")


def _metrics(rows: list[tuple[bool, bool]]) -> dict:
    tp = sum(p and d for p, d in rows)
    fp = sum(d and not p for p, d in rows)
    fn = sum(p and not d for p, d in rows)
    tn = len(rows) - tp - fp - fn
    div = lambda a, b: round(a / b, 4) if b else None  # noqa: E731
    return {"n": len(rows), "tp": tp, "fp": fp, "tn": tn, "fn": fn, "pass_rate": div(tp + tn, len(rows)),
            "precision": div(tp, tp + fp), "recall": div(tp, tp + fn), "fpr": div(fp, fp + tn)}


def _pct(xs: list[float]) -> dict:
    if len(xs) < 2:
        return {"p50": xs[0] if xs else None, "p95": xs[0] if xs else None}
    q = statistics.quantiles(xs, n=100)
    return {"p50": round(q[49], 3), "p95": round(q[94], 3)}


def run(policy: dict, cases: list[dict] | None = None) -> dict:
    content = dict(policy.get("content") or {})
    sig = content.get("signatures")
    if isinstance(sig, str) and not Path(sig).is_absolute():
        content["signatures"] = str(ROOT / sig)  # policy paths are relative to the repo root
    cases = load() if cases is None else cases
    by_source, by_control, lat = defaultdict(list), defaultdict(list), defaultdict(list)
    for c in cases:
        v = scan(c["text"], c["point"], content)
        row = (c["expect"] != "allow", detected(v))
        by_source[c["source"]].append(row)
        by_control[c["tags"][0]].append(row)
        for tier, ms in v.latency_ms.items():
            lat[tier].append(ms)
    controls = {k: {**_metrics(by_control.get(k, [])), "weight": w, "enabled": _enabled(content, k)} for k, w in WEIGHTS.items()}
    posture = sum(c["weight"] * c["enabled"] * (c["pass_rate"] or 0) for c in controls.values()) / sum(WEIGHTS.values())
    return {
        "overall": _metrics([r for rows in by_source.values() for r in rows]),
        "sources": {k: _metrics(v) for k, v in sorted(by_source.items())},
        "controls": controls,
        "latency_ms": {t: _pct(xs) for t, xs in lat.items()},
        "posture": round(posture, 4),
    }


def report(res: dict) -> str:
    f = lambda x: "  -  " if x is None else f"{x:5.3f}"  # noqa: E731
    head = f"{'source':16}{'n':>5}{'TP':>5}{'FP':>5}{'TN':>5}{'FN':>5}  prec   recall FPR   pass rate"
    line = lambda k, m: f"{k:16}{m['n']:5}{m['tp']:5}{m['fp']:5}{m['tn']:5}{m['fn']:5}  {f(m['precision'])}  {f(m['recall'])}  {f(m['fpr'])}  {f(m['pass_rate'])}"  # noqa: E731
    out = [head, *(line(k, m) for k, m in res["sources"].items()), line("OVERALL", res["overall"]), ""]
    out.append("control       weight on  pass rate")
    out += [f"{k:14}{c['weight']:6} {'y' if c['enabled'] else 'n':3} {f(c['pass_rate'])}" for k, c in res["controls"].items()]
    out.append("latency ms    " + "  ".join(f"{t} p50 {p['p50']} p95 {p['p95']}" for t, p in res["latency_ms"].items()))
    o = res["overall"]
    out.append(f"pass rate {o['pass_rate']:.3f}  FPR {f(o['fpr'])}  posture {res['posture']:.3f}")
    return "\n".join(out)


def main(policy_path: str = "policy.yaml", out: str = "audit/eval.json") -> dict:
    import yaml

    with open(ROOT / policy_path, encoding="utf-8") as fh:
        res = run(yaml.safe_load(fh))
    print(report(res))
    p = ROOT / out
    p.parent.mkdir(exist_ok=True)
    p.write_text(json.dumps(res, indent=1), encoding="utf-8")
    return res


if __name__ == "__main__":
    main()
