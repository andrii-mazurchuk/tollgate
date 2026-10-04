"""Shared test helpers."""
import contextlib

import httpx2


@contextlib.asynccontextmanager
async def gateway(monkeypatch, holder=None, *, base="http://127.0.0.1:8080", headers=None, client=("127.0.0.1", 123),
                  t2_off=False):
    """Full gateway app (scripted upstream) + an in-process httpx client, inside its lifespan. Yields (client, app,
    holder). Not a fixture: lifespan enter/exit must run in the same task."""
    monkeypatch.setenv("TOLLGATE_UPSTREAM", "scripted")
    if t2_off:
        monkeypatch.setenv("TOLLGATE_T2", "off")
    from tollgate.gateway import build_app
    from tollgate.gateway.policy import load_policy
    holder = holder or load_policy()
    app = build_app(holder)
    async with app.router.lifespan_context(app):
        async with httpx2.AsyncClient(transport=httpx2.ASGITransport(app=app, client=client), base_url=base, headers=headers) as c:
            yield c, app, holder


def policy_copy(tmp_path):
    """Holder on a tmp copy of policy.yaml: writes (profile switch, edits) never touch the repo's file."""
    from tollgate.gateway.policy import DEFAULT_PATH, load_policy
    path = tmp_path / "policy.yaml"
    path.write_bytes(DEFAULT_PATH.read_bytes())
    return load_policy(path)
