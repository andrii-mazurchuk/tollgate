import pytest

pytestmark = [pytest.mark.track_a]


@pytest.mark.xfail(strict=True, reason="AC2: not built yet. Remove this marker when green.")
def test_ac02_role_scoping():
    """AC2: /mcp/role-1 lists only role-1's tools; calling any other tool, or using role-1's key on /mcp/role-2, is rejected."""
    raise NotImplementedError
