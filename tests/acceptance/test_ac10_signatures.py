import pytest

pytestmark = [pytest.mark.track_b]


@pytest.mark.xfail(strict=True, reason="AC10: not built yet. Remove this marker when green.")
def test_ac10_signatures():
    """AC10: A new line in signatures.yaml blocks a previously allowed input without restart."""
    raise NotImplementedError
