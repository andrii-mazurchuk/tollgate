"""Golden test: every automatable Acme step (tollgate/scenario.yaml) through the real gateway over HTTP must PASS.

Steps that need the injection classifier (5.2) run in the slow variant only."""
import pytest

from tollgate import scenario

pytestmark = pytest.mark.track_a
SPEC = scenario.load()


async def _run(monkeypatch, skip_needs=()):
    monkeypatch.setenv("TOLLGATE_UPSTREAM", "scripted")  # model door steps: offline scripted model
    from tollgate.gateway import build_app
    from tollgate.gateway.policy import load_policy

    app = build_app(load_policy())
    r = scenario.Runner(app, SPEC)
    r.reset()
    out = []
    async with app.router.lifespan_context(app):
        for s in scenario.steps(SPEC):
            if not s["operator"] and s.get("needs") not in skip_needs:
                out.append(await r.run(s["id"]))
    r.reset()
    return out


async def test_acme_scenario_all_pass(monkeypatch):
    monkeypatch.setenv("TOLLGATE_T2", "off")
    res = await _run(monkeypatch, skip_needs=("classifier",))
    assert len(res) == 20  # 21 automatable steps minus 5.2
    assert [(x["id"], x["got"], x["why"]) for x in res if not x["pass"]] == []


@pytest.mark.slow
async def test_acme_scenario_with_classifier(monkeypatch):
    res = await _run(monkeypatch)
    assert [(x["id"], x["got"], x["why"]) for x in res if not x["pass"]] == []
