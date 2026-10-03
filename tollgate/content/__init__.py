"""Track B: local content pipeline. Entry point is scan(); see API_CONTRACT.md."""
from tollgate.contract import ScanPoint, Verdict


def scan(text: str, point: ScanPoint, policy: dict) -> Verdict:
    """Inspect text at a scan point under the policy's `content:` section.

    Stub until Track B merges tier 1: allows everything, so Track A can wire calls now.
    """
    return Verdict(action="allow")
