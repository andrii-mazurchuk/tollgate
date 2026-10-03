"""Track B: local content pipeline. Entry point is scan(); see API_CONTRACT.md."""
import time

from tollgate.content import tier2
from tollgate.content.normalise import decoded_runs, fold_variant, normalise, rot13
from tollgate.content.tier1 import find
from tollgate.contract import SEVERITY, Reason, ScanPoint, Verdict

MAX_SCAN_CHARS = 100_000  # policy `content.max_scan_chars`; bounds tier 1 regex time per scan


def find_inj(text: str, policy: dict) -> list:
    return find(text, policy, ("inj.", "sig."))


def scan(text: str, point: ScanPoint, policy: dict) -> Verdict:
    """Inspect text at a scan point under the policy's `content:` section. Never raises.

    Spans and redacted_text refer to the normalised text (NFKC, invisibles stripped).
    """
    t0 = time.perf_counter()
    try:
        policy = policy or {}
        cap = int(policy.get("max_scan_chars", MAX_SCAN_CHARS))
        truncated = len(text) > cap
        if truncated:  # head + tail: a payload padded to the end is still seen; the middle is not
            text = text[: cap // 2] + "\n[...]\n" + text[-(cap // 2):]
        if policy.get("normalise", True) is False:  # ablation switch (AC9): raw text, no decoding
            norm, transforms, runs = text, [], []
        else:
            norm, transforms = normalise(text)
            runs = decoded_runs(norm)
            variant, vt = fold_variant(norm)
            if variant is None and find_inj(rot13(norm), policy):  # rot13 only when it reveals an injection phrase
                variant, vt = rot13(norm), ["rot13"]
            if variant is not None:
                runs.append((0, len(norm), variant, "+".join(vt)))
        findings = find(norm, policy)
        claimed = [(s, e) for _, s, e, *_ in findings]
        for s, e, decoded, kind in runs:
            for k in kind.split("+"):
                if k not in transforms:
                    transforms.append(k)
            if (s, e) == (0, len(norm)):  # whole-text variant: injection/signature signal only, no spans to redact
                findings += [(r, s, e, a, mk, f"{d} ({kind})") for r, _, _, a, mk, d in find_inj(decoded, policy)]
                continue
            if any(s < ce and cs < e for cs, ce in claimed):
                continue
            # a finding inside a decoded run is reported on, and redacts, the whole run
            findings += [(r, s, e, a, mk, f"{d} ({kind})") for r, _, _, a, mk, d in find(decoded, policy)]

        latency = {"t1": round((time.perf_counter() - t0) * 1000, 3)}
        reasons = [Reason(rule=r, tier=1, detail=d, span=(s, e)) for r, s, e, _, _, d in findings]
        if truncated:
            reasons.append(Reason(rule="content.truncated", tier=1, detail=f"input over {cap} chars: scanned head and tail only"))
        t2_score, t2_block = _tier2(norm, [r[2] for r in runs], findings, point, policy, reasons, latency)

        action = max([f[3] for f in findings] + ["block"] * t2_block, key=SEVERITY.__getitem__, default="allow")
        redacted = None
        if action == "redact":
            redacted = _masked(norm, [f for f in findings if f[3] == "redact"])
        return Verdict(
            action=action,
            reasons=reasons,
            redacted_text=redacted,
            t2_score=t2_score,
            transforms=transforms,
            latency_ms=latency,
        )
    except Exception as exc:  # contract: scan never raises
        return Verdict(
            action="allow",
            reasons=[Reason(rule="content.error", tier=1, detail=f"{type(exc).__name__}: {exc}")],
            latency_ms={"t1": round((time.perf_counter() - t0) * 1000, 3)},
        )


def _masked(norm: str, findings) -> str:
    """norm with each finding span replaced by its mask(s)."""
    masks: dict[tuple[int, int], list[str]] = {}
    for _, s, e, _, mk, _ in findings:
        if mk not in masks.setdefault((s, e), []):
            masks[(s, e)].append(mk)
    parts, pos = [], 0
    for (s, e), mks in sorted(masks.items()):
        parts += [norm[pos:s], " ".join(mks)]
        pos = e
    return "".join(parts) + norm[pos:]


# injection is the main threat on inbound text only (TOLLGATE 4.5); outbound args/responses stay tier 1
T2_POINTS = ("prompt", "tool_result")


def _tier2(norm, decoded, findings, point, policy, reasons, latency) -> tuple[float | None, bool]:
    """Gated classifier. Sync at `sync_points`, on short text or a tier 1 inj.* escalation, else deferred.

    Scores the text with tier 1 PII/secret spans masked: a payee line with an IBAN is PII, not injection.
    Returns (score, block).
    """
    inj = policy.get("injection")
    if not isinstance(inj, dict) or "high" not in inj or point not in inj.get("points", T2_POINTS):
        return None, False  # no thresholds in the policy = tier 2 off
    t0 = time.perf_counter()
    escalated = any(f[0].startswith("inj.") for f in findings)
    text = _masked(norm, [f for f in findings if f[0].startswith(("pii.", "secret."))])
    n = tier2.n_tokens(norm)  # gate on the raw length: masking must not pull a deferred text into sync
    if n is None:
        reasons.append(Reason(rule="t2.unavailable", tier=2, detail="classifier not loaded"))
        return None, False
    sample = None
    if not escalated and point not in inj.get("sync_points", ()) and n > inj.get("sync_max_tokens", 64):
        sample = int(inj.get("sample_chunks", 0))
        if not sample:
            reasons.append(Reason(rule="t2.deferred", tier=2, detail=f"{n} tokens > sync_max_tokens"))
            return None, False  # ponytail: no async audit scoring yet; taint covers long tool results
        # long un-escalated text: score `sample` evenly spaced 256-token chunks (first and last included), bounded latency
        reasons.append(Reason(rule="t2.sampled", tier=2, detail=f"{n} tokens: scored {sample} chunks"))
    scores = [tier2.score(t, sample) if sample else tier2.score(t) for t in [text, *decoded]]
    latency["t2"] = round((time.perf_counter() - t0) * 1000, 3)
    if None in scores:
        reasons.append(Reason(rule="t2.unavailable", tier=2, detail="classifier failed"))
        return None, False
    best = max(scores)
    high, low = inj["high"], inj.get("low", inj["high"])
    if best >= high:
        reasons.append(Reason(rule="t2.injection", tier=2, detail=f"injection score {best:.4f} >= high {high}"))
    elif best >= low:
        reasons.append(Reason(rule="t2.suspect", tier=2, detail=f"injection score {best:.4f} in [low {low}, high {high})"))
    # TOLLGATE 4.5: balanced flags a tool result injection and relies on taint; strict sets tool_result_action: block
    flag_only = point == "tool_result" and inj.get("tool_result_action", "flag") == "flag"
    return best, best >= high and not flag_only
