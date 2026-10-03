import pytest

pytestmark = [pytest.mark.track_b]


@pytest.mark.xfail(strict=True, reason="AC8 (PII part): not built yet. Remove this marker when green.")
def test_ac08_pii():
    """AC8 (PII part): scan(): valid IBAN redacted, valid PESEL blocked, checksum-failing look-alikes ignored."""
    raise NotImplementedError
