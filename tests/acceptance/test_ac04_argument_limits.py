import pytest

pytestmark = [pytest.mark.track_a]


@pytest.mark.xfail(strict=True, reason="AC4: not built yet. Remove this marker when green.")
def test_ac04_argument_limits():
    """AC4: SELECT passes and DELETE is blocked on the same tool; a path outside the glob is blocked."""
    raise NotImplementedError
