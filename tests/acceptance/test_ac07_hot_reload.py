import pytest

pytestmark = [pytest.mark.track_a]


@pytest.mark.xfail(strict=True, reason="AC7: not built yet. Remove this marker when green.")
def test_ac07_hot_reload():
    """AC7: A policy edit applies on the next call without restart; an invalid file is rejected and the old policy kept."""
    raise NotImplementedError
