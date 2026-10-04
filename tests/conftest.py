import pytest


@pytest.fixture(autouse=True)
def _audit_to_tmp(tmp_path, monkeypatch):
    """No test writes the real audit/events.jsonl; tests that set their own path override this."""
    monkeypatch.setenv("TOLLGATE_AUDIT", str(tmp_path / "audit.jsonl"))
    monkeypatch.setenv("TOLLGATE_PEERS", str(tmp_path / "peers.json"))  # nor the real peer registry


@pytest.fixture(autouse=True)
def _tests_allow_unenrolled_keys(monkeypatch):
    """Most tests call the doors with hand-issued keys (keys.issue): a policy that does not set allow_unenrolled_keys
    lets them in here. Tests of the production default set allow_unenrolled_keys: false on their policy copy."""
    from tollgate.gateway import keys
    monkeypatch.setattr(keys, "unenrolled_ok", lambda data: data.get("allow_unenrolled_keys", True) is True)


@pytest.fixture(autouse=True)
def _fresh_budgets():
    """Token budgets are process-wide per (role, UTC day); without this, earlier tests' spend leaks into AC11."""
    from tollgate.gateway import model_door
    model_door.USED.clear()
    yield
    model_door.USED.clear()


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
