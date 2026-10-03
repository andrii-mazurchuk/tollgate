import pytest


@pytest.fixture(autouse=True)
def _tier2_off_for_fast_gateway_tests(request, monkeypatch):
    """Track A gateway tests not marked slow run with tier 2 off: the first tool-result scan would otherwise load
    the 739 MB classifier (~4 s) in whichever test happens to run first. Content tests (track_b) are untouched."""
    if request.node.get_closest_marker("track_a") and not request.node.get_closest_marker("slow"):
        monkeypatch.setenv("TOLLGATE_T2", "off")


@pytest.hookimpl(trylast=True)  # after -m deselection: the fast suite never downloads
def pytest_collection_modifyitems(items):
    """Cold cache: AC8's `needs_model` skipif was decided at import. If such tests are still selected, download the
    tier 2 model once and lift the skip; offline, keep it with the download error as the reason."""
    gated = [(i, m) for i in items for m in i.own_markers
             if m.name == "skipif" and str(m.kwargs.get("reason", "")).startswith("tier 2 model")]
    if not gated:
        return
    try:
        from huggingface_hub import hf_hub_download

        from tollgate.content.tier2 import REPO
        for f in ("onnx/tokenizer.json", "onnx/model.onnx"):
            hf_hub_download(REPO, f)
        repl = None
    except Exception as exc:
        repl = pytest.mark.skip(reason=f"tier 2 model unavailable (download failed: {type(exc).__name__}: {exc})").mark
    for item, m in gated:
        item.own_markers.remove(m)
        if repl:
            item.own_markers.append(repl)
