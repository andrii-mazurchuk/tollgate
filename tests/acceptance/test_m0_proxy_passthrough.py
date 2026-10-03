import pytest

pytestmark = [pytest.mark.track_a]


@pytest.mark.xfail(strict=True, reason="M0 gate: not built yet. Remove this marker when green.")
def test_m0_proxy_passthrough():
    """M0 gate: tools/list through the Tollgate proxy equals the mock github server's list, and a tools/call round-trips (in-memory fastmcp Client)."""
    raise NotImplementedError
