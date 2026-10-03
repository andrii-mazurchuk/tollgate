"""Track B: posture uses the full corpus for a control whose held-out slice is too small (n < 10)."""
import pytest

from tollgate.eval import runner

pytestmark = [pytest.mark.track_b]


def test_small_control_posture_uses_full_corpus():
    cases = [{"id": f"s{i}", "text": f"key AKIA{i:016d}"[:24], "point": "tool_result", "expect": "block",
              "source": "own", "tags": ["secrets"]} for i in range(12)]
    res = runner.run({"content": {"secrets": "block"}}, cases)
    sec = res["controls"]["secrets"]
    assert sec["n"] < 10 and sec["posture_basis"] == "full corpus" and sec["posture_n"] == 12
    assert "full corpus" in runner.report(res)
