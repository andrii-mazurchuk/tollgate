"""Track B: local content pipeline. Entry point is scan(); see API_CONTRACT.md."""
import time

from tollgate.content.normalise import base64_runs, normalise
from tollgate.content.tier1 import find
from tollgate.contract import SEVERITY, Reason, ScanPoint, Verdict


def scan(text: str, point: ScanPoint, policy: dict) -> Verdict:
    """Inspect text at a scan point under the policy's `content:` section. Never raises.

    Spans and redacted_text refer to the normalised text (NFKC, invisibles stripped).
    """
    t0 = time.perf_counter()
    try:
        policy = policy or {}
        norm, transforms = normalise(text)
        findings = find(norm, policy)
        claimed = [(s, e) for _, s, e, *_ in findings]
        for s, e, decoded in base64_runs(norm):
            if "base64" not in transforms:
                transforms.append("base64")
            if any(s < ce and cs < e for cs, ce in claimed):
                continue
            # a finding inside a decoded run is reported on, and redacts, the whole run
            findings += [(r, s, e, a, mk, d + " (base64)") for r, _, _, a, mk, d in find(decoded, policy)]

        action = max((f[3] for f in findings), key=SEVERITY.__getitem__, default="allow")
        redacted = None
        if action == "redact":
            masks: dict[tuple[int, int], list[str]] = {}
            for _, s, e, _, mk, _ in findings:
                if mk not in masks.setdefault((s, e), []):
                    masks[(s, e)].append(mk)
            parts, pos = [], 0
            for (s, e), mks in sorted(masks.items()):
                parts += [norm[pos:s], " ".join(mks)]
                pos = e
            redacted = "".join(parts) + norm[pos:]
        return Verdict(
            action=action,
            reasons=[Reason(rule=r, tier=1, detail=d, span=(s, e)) for r, s, e, _, _, d in findings],
            redacted_text=redacted,
            transforms=transforms,
            latency_ms={"t1": round((time.perf_counter() - t0) * 1000, 3)},
        )
    except Exception as exc:  # contract: scan never raises
        return Verdict(
            action="allow",
            reasons=[Reason(rule="content.error", tier=1, detail=f"{type(exc).__name__}: {exc}")],
            latency_ms={"t1": round((time.perf_counter() - t0) * 1000, 3)},
        )
