import pytest

pytestmark = [pytest.mark.track_a]


@pytest.mark.xfail(strict=True, reason="AC3: not built yet. Remove this marker when green.")
def test_ac03_exact_tools():
    """AC3: An exact tool list (tools: [...]) is honoured: excluded tools are absent from tools/list and rejected on call."""
    raise NotImplementedError
