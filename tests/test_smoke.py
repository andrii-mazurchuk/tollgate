"""Demo-path smoke checks. scripts/smoke.sh runs `pytest -m smoke`; it must pass before every merge to main.

Grow this as the demo path grows: one check per demo step, real components only.
"""
import pytest

from tollgate.content import scan
from tollgate.contract import Verdict

pytestmark = pytest.mark.smoke


def test_scan_honours_contract():
    v = scan("hello", "prompt", {})
    assert isinstance(v, Verdict)
    assert v.action in {"allow", "redact", "approve", "block"}
