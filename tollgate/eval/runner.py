"""Offline evaluation: scan() over tests/corpus, per-source confusion matrix, latency, posture score (TOLLGATE §6).

Every case is scanned; cases are split 70/30 by a fixed hash of their id. Tier 2 `high` is swept on the 70 only,
and every reported metric comes from the held-out 30. Tier 2 scores are cached in audit/t2_cache.json.
"""
import copy
import hashlib
import json
import statistics
from collections import defaultdict
from pathlib import Path

from tollgate.content import scan, tier2
from tollgate.content.normalise import normalise
from tollgate.eval.corpus import CORPUS, load

WEIGHTS = {"pii": 3, "secrets": 3, "injection": 3, "signatures": 1, "obfuscation": 1}
ROOT = CORPUS.parents[1]
CACHE = ROOT / "audit" / "t2_cache.json"
PROFILES = {"strict": 0.10, "balanced": 0.05, "lenient": 0.02}  # benign FPR ceiling when choosing tier 2 `high`
NEVER = 1.01  # a `high` tier 2 can never reach


def detected(v, expect: str = "flag") -> bool:
    """block/redact cases pass only when that action is produced; flag/allow cases count any detection."""
    if expect in ("block", "redact"):
        return v.action == expect
    return v.action != "allow" or any(r.rule.startswith(("inj.", "sig.", "t2.injection")) for r in v.reasons)


def train(case: dict) -> bool:
    """Fixed 70/30 split: stable across runs and corpus rebuilds."""
    return int(hashlib.sha256(case["id"].encode()).hexdigest(), 16) % 100 < 70


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


def _content(policy: dict) -> dict:
    content = copy.deepcopy(policy.get("content") or {})
    sig = content.get("signatures")
    if isinstance(sig, str) and not Path(sig).is_absolute():
        content["signatures"] = str(ROOT / sig)  # policy paths are relative to the repo root
    return content


def _at(rows: list[tuple[bool, bool, float | None]], h: float) -> dict:
    """rows: (positive, detected without tier 2, sync tier 2 score). Metrics if tier 2 blocks at score >= h."""
    return _metrics([(p, d or (s is not None and s >= h)) for p, d, s in rows])


def _sweep(rows: list[tuple[bool, bool, float | None]], low: float) -> dict:
    """Per profile: the lowest `high` whose FPR is within the ceiling (= max recall, FPR falls as `high` rises).

    The grid starts at `low`: a `high` below `low` would invert the suspect band.
    """
    grid = [low, *sorted({s for _, _, s in rows if s is not None and s > low}), NEVER]
    out = {}
    for name, ceil in PROFILES.items():
        h = next((h for h in grid if (_at(rows, h)["fpr"] or 0) <= ceil), NEVER)
        out[name] = {"high": h, "fpr_ceiling": ceil, "train": _at(rows, h)}
    return out


def run(policy: dict, cases: list[dict] | None = None) -> dict:
    content = _content(policy)
    cases = load() if cases is None else cases
    inj = content.get("injection")
    tier2.CACHE = json.loads(CACHE.read_text()) if CACHE.exists() else {}
    try:
        return _run(content, cases, inj if isinstance(inj, dict) and "high" in inj else None)
    finally:
        if tier2.CACHE:
            CACHE.parent.mkdir(exist_ok=True)
            CACHE.write_text(json.dumps(tier2.CACHE))
        tier2.CACHE = None


def _run(content: dict, cases: list[dict], inj: dict | None) -> dict:
    by_source, by_control, lat = defaultdict(list), defaultdict(list), defaultdict(list)
    sync, t2_ms = 0, []
    for c in cases:
        v = scan(c["text"], c["point"], content)
        if "t2" in v.latency_ms:
            sync += 1
            hit = tier2.CACHE.get(hashlib.sha256(normalise(c["text"])[0].encode()).hexdigest())
            if hit:
                t2_ms.append(hit[1])  # model time from the first (uncached) run; cached reruns read ~0
        if not train(c):
            row = (c["expect"] != "allow", detected(v, c["expect"]))
            by_source[c["source"]].append(row)
            by_control[c["tags"][0]].append(row)
            lat["t1"].append(v.latency_ms["t1"])  # t2 time comes from the score cache (model time), below
    controls = {k: {**_metrics(by_control.get(k, [])), "weight": w, "enabled": _enabled(content, k)} for k, w in WEIGHTS.items()}
    posture = sum(c["weight"] * c["enabled"] * (c["pass_rate"] or 0) for c in controls.values()) / sum(WEIGHTS.values())
    res = {
        "cases_run": len(cases),
        "split": "held-out 30% (sha256(id) % 100 >= 70); thresholds tuned on the other 70%",
        "overall": _metrics([r for rows in by_source.values() for r in rows]),
        "sources": {k: _metrics(v) for k, v in sorted(by_source.items())},
        "controls": controls,
        "latency_ms": {t: _pct(xs) for t, xs in lat.items()},
        "posture": round(posture, 4),
        "ablation": _ablation(content, cases),
    }
    if inj is not None:
        res["tier2"] = {"sync_share": round(sync / len(cases), 4), "sync_n": sync, "latency_ms": _pct(t2_ms),
                        **_calibrate(content, [c for c in cases if c["tags"][0] == "injection"], inj)}
    return res


def _calibrate(content: dict, cases: list[dict], inj: dict) -> dict:
    """Sweep `high` on the 70; report each profile on the held-out 30, also as if deferred texts had been scored."""
    probe = {**content, "injection": {**inj, "high": 2.0, "low": 2.0}}  # tier 2 runs as gated but never decides
    fit, test, test_async = [], [], []
    for c in cases:
        v = scan(c["text"], c["point"], probe)
        row = (c["expect"] != "allow", detected(v, c["expect"]), v.t2_score)
        if train(c):
            fit.append(row)
            continue
        test.append(row)
        if any(r.rule == "t2.deferred" for r in v.reasons):
            row = (*row[:2], tier2.score(normalise(c["text"])[0]))
        test_async.append(row)
    profiles = _sweep(fit, inj.get("low", 0.0))
    for p in profiles.values():
        p["held_out"] = _at(test, p["high"])
        p["held_out_if_async_scored"] = _at(test_async, p["high"])
    return {"profiles": profiles}


def _ablation(content: dict, cases: list[dict]) -> dict:
    """AC9: recall on obfuscated variants vs their plain originals, normalisation on vs off (all 16 own cases)."""
    out = {}
    for mode, extra in (("on", {}), ("off", {"normalise": False})):
        cfg = {**content, **extra}
        for src, name in (("own_obf_plain", "plain"), ("own_obf", "obfuscated")):
            rows = [(True, detected(scan(c["text"], c["point"], cfg), c["expect"])) for c in cases if c["source"] == src]
            out[f"{name}_{mode}"] = _metrics(rows)["recall"]
    return out


def report(res: dict) -> str:
    f = lambda x: "  -  " if x is None else f"{x:5.3f}"  # noqa: E731
    head = f"{'source':16}{'n':>5}{'TP':>5}{'FP':>5}{'TN':>5}{'FN':>5}  prec   recall FPR   pass rate"
    line = lambda k, m: f"{k:16}{m['n']:5}{m['tp']:5}{m['fp']:5}{m['tn']:5}{m['fn']:5}  {f(m['precision'])}  {f(m['recall'])}  {f(m['fpr'])}  {f(m['pass_rate'])}"  # noqa: E731
    out = [f"HELD-OUT 30% of {res['cases_run']} cases run", head, *(line(k, m) for k, m in res["sources"].items()), line("OVERALL", res["overall"]), ""]
    out.append("control       weight on  pass rate")
    out += [f"{k:14}{c['weight']:6} {'y' if c['enabled'] else 'n':3} {f(c['pass_rate'])}" for k, c in res["controls"].items()]
    out.append("latency ms    " + "  ".join(f"{t} p50 {p['p50']} p95 {p['p95']}" for t, p in res["latency_ms"].items()))
    if "tier2" in res:
        t = res["tier2"]
        out.append(f"tier 2 sync share {t['sync_share']:.3f} ({t['sync_n']}/{res['cases_run']}), model ms p50 {t['latency_ms']['p50']} p95 {t['latency_ms']['p95']}")
        out.append("profile   high (tuned on 70%)  held-out inj recall  FPR    | if deferred texts scored: recall  FPR")
        for k, p in t["profiles"].items():
            h, a = p["held_out"], p["held_out_if_async_scored"]
            out.append(f"{k:9} {p['high']:<20.4g} {f(h['recall'])}                {f(h['fpr'])}  |                           {f(a['recall'])}  {f(a['fpr'])}")
    a = res["ablation"]
    out.append("AC9 recall    norm on: plain {} obf {}   norm off: plain {} obf {}".format(
        *(f(a[k]) for k in ("plain_on", "obfuscated_on", "plain_off", "obfuscated_off"))))
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
