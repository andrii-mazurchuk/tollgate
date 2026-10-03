import pytest

pytestmark = [pytest.mark.track_b]


@pytest.mark.xfail(strict=True, reason="AC13 (small): not built yet. Remove this marker when green.")
def test_ac13_suite_summary():
    """AC13 (small): `tollgate test` prints pass rate, false-positive rate and posture score."""
    raise NotImplementedError
