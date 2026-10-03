"""AC13 (small): `tollgate test` prints pass rate, false-positive rate and posture score; disabling a control lowers posture."""
import copy

import pytest
import yaml

from tollgate.eval import runner

pytestmark = [pytest.mark.track_b]


@pytest.fixture(scope="module")
def policy():
    with open("policy.yaml", encoding="utf-8") as f:
        return yaml.safe_load(f)


@pytest.fixture(scope="module")
def result(policy):
    return runner.run(policy)


def test_ac13_suite_summary(result):
    assert result["cases_run"] >= 500 and result["overall"]["n"] < result["cases_run"]  # report is held-out only
    assert {"pii", "secrets", "injection", "signatures", "obfuscation"} <= set(result["controls"])
    text = runner.report(result)
    for needle in ("pass rate", "FPR", "posture"):
        assert needle in text
    assert 0 < result["posture"] <= 1


def test_ac13_disabling_injection_drops_posture(policy, result):
    off = copy.deepcopy(policy)
    off["content"]["injection"] = False
    assert runner.run(off)["posture"] < result["posture"]
