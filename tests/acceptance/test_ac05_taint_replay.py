import pytest

pytestmark = [pytest.mark.track_a]


@pytest.mark.xfail(strict=True, reason="AC5: not built yet. Remove this marker when green.")
def test_ac05_taint_replay():
    """AC5: GitHub attack trace leaks with taint disabled and is blocked with the named cause with taint enabled."""
    raise NotImplementedError
