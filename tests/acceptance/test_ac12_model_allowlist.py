import copy
import json

import pytest

from tests.acceptance.door_stub import SEEN, ask, door

pytestmark = [pytest.mark.track_a]
URL = "/v1/chat/completions"


def _policy():
    from tollgate.gateway.policy import load_policy
    p = copy.deepcopy(load_policy().data)
    p["roles"]["role-1"].update(models=["qwen3:1.7b"], budget={"tokens_per_day": 10**6})
    p["roles"]["role-2"].update(models=["qwen3:4b"], budget={"tokens_per_day": 10**6})
    return p


def _events(tmp_path):
    return [json.loads(x) for x in (tmp_path / "events.jsonl").read_text(encoding="utf-8").splitlines()]


async def test_ac12_model_not_listed_is_rejected(tmp_path, monkeypatch):
    """AC12: a model not in roles.<role>.models gets 403 model.denied; a listed one is forwarded."""
    from tollgate.gateway.keys import issue

    app, client = door(_policy(), monkeypatch, tmp_path)
    k1 = {"authorization": f"Bearer {issue('role-1')}"}
    async with app.router.lifespan_context(app), client() as c:
        r = await c.post(URL, json=ask("qwen3:4b", "hi"), headers=k1)
        assert r.status_code == 403 and r.json()["error"]["code"] == "model.denied"
        assert SEEN == []  # never reached the upstream

        r = await c.post(URL, json=ask("qwen3:1.7b", "hi"), headers=k1)
        assert r.status_code == 200 and r.json()["choices"][0]["message"]["content"] == "echo: hi"
        assert "authorization" not in SEEN[0]["headers"]  # the role key is not forwarded upstream

        assert (await c.post(URL, json=ask("qwen3:1.7b", "hi"))).status_code == 401
        bad = {"authorization": f"Bearer {issue('role-1')}x"}
        assert (await c.post(URL, json=ask("qwen3:1.7b", "hi"), headers=bad)).status_code == 401
        r = await c.post(URL, json=ask("qwen3:1.7b", "hi", stream=True), headers=k1)
        assert r.status_code == 400 and "stream" in r.json()["error"]["message"]

    model = [e for e in _events(tmp_path) if e["door"] == "model"]
    denied = [e for e in model if e["verdict"] == "block"]
    assert denied and denied[0]["reasons"][0]["rule"] == "model.denied"
    ok = [e for e in model if e["verdict"] == "allow"]
    assert ok and ok[0]["tokens"] == 600 and ok[0]["role"] == "role-1" and ok[0]["tool"] == "qwen3:1.7b"


async def test_ac12_door_scans_prompt_and_response(tmp_path, monkeypatch):
    """Model door runs scan() on the prompt (block / redact before forwarding) and on the response."""
    from tollgate.gateway.keys import issue

    app, client = door(_policy(), monkeypatch, tmp_path)
    k1 = {"authorization": f"Bearer {issue('role-1')}"}
    async with app.router.lifespan_context(app), client() as c:
        r = await c.post(URL, json=ask("qwen3:1.7b", "PESEL 44051401359"), headers=k1)
        assert r.status_code == 400 and "pii.pesel" in r.text
        assert SEEN == []

        iban = "PL61 1090 1014 0000 0712 1981 2874"
        # wording matters: tier 2 (balanced, high 0.50) flags terse "Account: <IBAN>" prompts as injection
        r = await c.post(URL, json=ask("qwen3:1.7b", f"Summarise this invoice. Account: {iban}"), headers=k1)
        assert r.status_code == 200
        sent = SEEN[-1]["messages"][-1]["content"]
        assert iban not in sent and "2874" in sent

        r = await c.post(URL, json=ask("qwen3:1.7b", "Summarise the deployment notes for the leak review."), headers=k1)
        assert r.status_code == 400 and "secret.aws_key" in r.text and "AKIA" not in r.text
