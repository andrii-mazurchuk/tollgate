"""Security hardening regressions (h/hardening): each test failed before its fix."""
import hashlib
import hmac

import pytest

from tollgate.gateway import keys


def test_no_constant_key_secret(tmp_path, monkeypatch):
    monkeypatch.delenv("TOLLGATE_KEY_SECRET", raising=False)
    monkeypatch.setenv("TOLLGATE_SECRET_FILE", str(tmp_path / "secret.key"))
    forged = hmac.new(b"tollgate-dev-secret-change-me", b"dev:k1", hashlib.sha256).hexdigest()[:32]
    assert keys.verify(f"tg_dev_k1_{forged}") is None  # a key forged from the public repo is refused
    k = keys.issue("dev", "k1")
    assert keys.verify(k) == ("dev", "k1") and len((tmp_path / "secret.key").read_bytes()) >= 32


def test_no_constant_feed_secret(tmp_path, monkeypatch):
    from tollgate import feed
    monkeypatch.delenv("TOLLGATE_FEED_SECRET", raising=False)
    monkeypatch.setenv("TOLLGATE_SECRET_FILE", str(tmp_path / "secret.key"))
    canon = b'{"version":1}'
    assert feed._sig({"version": 1}) != hmac.new(b"tollgate-dev-feed-secret", canon, hashlib.sha256).hexdigest()


from tests.test_hook_door import _app, _decision, _events, _hook, _key  # noqa: E402

AWS = "AKIAIOSFODNN7EXAMPLE"


@pytest.mark.track_a
async def test_hook_pass_through_is_exact_server_name(monkeypatch):
    async with _app(monkeypatch) as c:
        k = _key()
        await _hook(c, k, "PreToolUse", "mcp__tollgate-notes__x", {"q": "hi"})
        assert _events()[-1]["tool"] == "mcp__tollgate-notes__x"  # checked and audited, not passed through
