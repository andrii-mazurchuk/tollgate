import os
import tempfile

import pytest

from tollgate.mocks.files import FS as _FS

ADMIN_TOKEN = "test-admin-token"
ADMIN = {"Authorization": f"Bearer {ADMIN_TOKEN}"}

_FS0 = dict(_FS)  # mock files server contents at import


def pytest_configure(config):
    """One isolated install secret per test run (keys minted at import must still verify in every test)."""
    if not os.environ.get("TOLLGATE_SECRET_FILE"):
        os.environ["TOLLGATE_SECRET_FILE"] = os.path.join(tempfile.mkdtemp(prefix="tollgate-test-"), "secret.key")


@pytest.fixture(autouse=True)
def _audit_to_tmp(request, tmp_path, monkeypatch):
    """No test writes the real audit/events.jsonl; tests that set their own path override this. Any TOLLGATE_* the
    developer's shell carries is dropped first (except the per-run secret file set in pytest_configure)."""
    for k in [k for k in os.environ if k.startswith("TOLLGATE_") and k != "TOLLGATE_SECRET_FILE"]:
        monkeypatch.delenv(k)
    if not request.node.get_closest_marker("slow"):  # fast eval runs never rewrite audit/t2_cache.json
        monkeypatch.setenv("TOLLGATE_T2_CACHE", str(tmp_path / "t2_cache.json"))
    monkeypatch.setenv("TOLLGATE_AUDIT", str(tmp_path / "audit.jsonl"))
    monkeypatch.setenv("TOLLGATE_PEERS", str(tmp_path / "peers.json"))  # nor the real peer registry
    monkeypatch.setenv("TOLLGATE_ACCOUNTS", str(tmp_path / "accounts.json"))  # nor the real console accounts
    monkeypatch.setenv("TOLLGATE_ADMIN_TOKEN", ADMIN_TOKEN)  # no default token exists; tests that write send it


@pytest.fixture(autouse=True)
def _tests_allow_unenrolled_keys(monkeypatch):
    """Most tests call the doors with hand-issued keys (keys.issue): a policy that does not set allow_unenrolled_keys
    lets them in here. Tests of the production default set allow_unenrolled_keys: false on their policy copy."""
    from tollgate.gateway import keys
    monkeypatch.setattr(keys, "unenrolled_ok", lambda data: data.get("allow_unenrolled_keys", True) is True)


def _reset_globals():
    """Process-wide in-memory state (budgets, taint, caches, mock servers, the console eval run) back to import time."""
    from tollgate.mocks import files, github
    from tollgate import accounts, edge
    from tollgate.console import threat_feed as console_feed
    from tollgate.gateway import UPSTREAMS, model_door, peers, taint
    for d in (model_door.USED, taint.STATE, UPSTREAMS, edge._CACHE, peers._CACHE, accounts._CACHE, accounts._FAILS,
              console_feed._TASKS, github.PRS, files.FS):
        d.clear()
    files.FS.update(_FS0)
    console_feed.RUN.update(running=False, started_at=None, error=None)


@pytest.fixture(autouse=True)
def _fresh_globals():
    """Without this, one test's budget spend, taint or cache leaks into the next (e.g. AC11 budgets)."""
    _reset_globals()
    yield
    _reset_globals()


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

        from tollgate.content.tier2 import REPO, REVISION
        for f in ("onnx/tokenizer.json", "onnx/model.onnx"):
            hf_hub_download(REPO, f, revision=REVISION)
        repl = None
    except Exception as exc:
        repl = pytest.mark.skip(reason=f"tier 2 model unavailable (download failed: {type(exc).__name__}: {exc})").mark
    for item, m in gated:
        item.own_markers.remove(m)
        if repl:
            item.own_markers.append(repl)
