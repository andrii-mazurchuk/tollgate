import pytest

pytestmark = [pytest.mark.track_a]


@pytest.mark.xfail(strict=True, reason="AC6: not built yet. Remove this marker when green.")
def test_ac06_benign_flow():
    """AC6: Read a public issue, then open a PR with no private read: allowed."""
    raise NotImplementedError
