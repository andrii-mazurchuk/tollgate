import pytest


@pytest.fixture(autouse=True)
def _tier2_off_for_fast_gateway_tests(request, monkeypatch):
    """Track A gateway tests not marked slow run with tier 2 off: the first tool-result scan would otherwise load
    the 739 MB classifier (~4 s) in whichever test happens to run first. Content tests (track_b) are untouched."""
    if request.node.get_closest_marker("track_a") and not request.node.get_closest_marker("slow"):
        monkeypatch.setenv("TOLLGATE_T2", "off")
