"""Edge UI v3: the full local agent setup (/edge/api/agent) and local settings that may only be stricter than the
company policy (/edge/api/settings), plus the text store obeying "keep full text"."""
import json

import httpx2
import pytest

from tollgate.gateway import local_text
from tests.test_edge_api import _edge

pytestmark = pytest.mark.track_a


@pytest.fixture(autouse=True)
def _settings_to_tmp(tmp_path, monkeypatch):
    monkeypatch.setenv("TOLLGATE_EDGE_SETTINGS", str(tmp_path / "edge_settings.json"))
    monkeypatch.setenv("TOLLGATE_LOCAL_TEXT", str(tmp_path / "local_text.jsonl"))


def test_stricter_only_rule():
    ceil = {"keep_text": True, "retention": 2000}
    assert local_text.check_settings({"keep_text": False, "retention": 50, "theme": "dark"}, ceil) == \
        {"keep_text": False, "retention": 50, "theme": "dark"}
    with pytest.raises(ValueError, match="company policy"):
        local_text.check_settings({"retention": 5000}, ceil)
    with pytest.raises(ValueError, match="company policy"):
        local_text.check_settings({"keep_text": True}, {"keep_text": False, "retention": 2000})
    for bad in ({"retention": 0}, {"retention": "10"}, {"keep_text": "yes"}, {"theme": "pink"}, {"other": 1}):
        with pytest.raises(ValueError):
            local_text.check_settings(bad, ceil)
    assert local_text.ceiling({"edge": {"keep_text": False, "retention": 100}}) == {"keep_text": False, "retention": 100}
    assert local_text.ceiling({}) == {"keep_text": True, "retention": local_text.KEEP}


def test_text_store_obeys_keep_text_and_retention():
    local_text.save_settings({"keep_text": False})
    local_text.write("t_1", {"args": {"original": "a", "sent": "a", "spans": []}})
    assert local_text.load() == {}
    local_text.save_settings({"keep_text": True, "retention": 3})
    for i in range(5):
        local_text.write(f"t_{i}", {"args": {"original": "a", "sent": "a", "spans": []}})
    local_text.trim(local_text.path())
    assert sorted(local_text.load()) == ["t_2", "t_3", "t_4"]


async def test_agent_setup_lists_allowed_and_denied_tools(monkeypatch):
    async with _edge(monkeypatch) as (c, _):
        a = (await c.get("/edge/api/agent")).json()
        assert a["role"] == "role-2" and a["models"] == ["qwen3:4b"] and a["budget"]["limit"] == 500000
        srv = {s["name"]: s for s in a["servers"]}
        assert set(srv) == {"github", "tickets", "files"} and all(s["reachable"] for s in srv.values())
        assert [t["name"] for t in srv["files"]["denied"]] == ["files.fs.delete"]
        allowed = {t["name"]: t for s in srv.values() for t in s["allowed"]}
        assert any("/workspace" in x for x in allowed["files.fs.read"]["limits"])
        assert any("SELECT" in x for x in allowed["tickets.query"]["limits"])
        assert allowed["github.pr.create"]["write"] and not allowed["github.issues.read"]["write"]
        labels = {x["tool"]: x for x in a["labels"]}
        assert labels["github.pr.create"]["words"] == ["public destination"]
        assert a["flow_rule"]["action"] == "block" and "public destination" in a["flow_rule"]["sentence"]
        assert "Secrets" in a["content"]["masked"] and "PESEL numbers" in a["content"]["blocked"]
        assert a["content"]["signatures"]["count"] > 0 and "50%" in a["content"]["injection"]["words"]
        assert a["policy"]["managed_by"] == "your security team"


async def test_settings_api_persists_and_refuses_looser(monkeypatch, tmp_path):
    async with _edge(monkeypatch) as (c, app):
        s = (await c.get("/edge/api/settings")).json()
        assert s["settings"] == {"keep_text": True, "retention": local_text.KEEP, "theme": "system"}
        assert s["ceiling"] == {"keep_text": True, "retention": local_text.KEEP}
        r = await c.post("/edge/api/settings", json={"keep_text": False, "retention": 100})
        assert r.status_code == 200 and r.json()["settings"]["keep_text"] is False
        assert json.loads((tmp_path / "edge_settings.json").read_text())["retention"] == 100
        r = await c.post("/edge/api/settings", json={"retention": 10 ** 6})
        assert r.status_code == 400 and "company policy" in r.json()["error"]
        assert (await c.post("/edge/api/settings", content=b"nope")).status_code == 400
        async with httpx2.AsyncClient(transport=httpx2.ASGITransport(app=app, client=("10.1.2.3", 5000)),
                                      base_url="http://x") as remote:
            assert (await remote.post("/edge/api/settings", json={"keep_text": False})).status_code == 403
            assert (await remote.get("/edge/api/agent")).status_code == 403
