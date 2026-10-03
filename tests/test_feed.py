"""P6: signatures come from an externally managed feed (signed bundle), pulled into signatures.yaml."""
import shutil
from pathlib import Path

import httpx2
import pytest

from tollgate.content import scan
from tollgate.feed import Puller, build_feed_app, bundle, publish

pytestmark = [pytest.mark.track_a]
SEED = Path(__file__).resolve().parents[1] / "feed" / "bundle_src.yaml"


@pytest.fixture
def env(tmp_path):
    src = tmp_path / "feed"
    src.mkdir()
    shutil.copy(SEED, src / "bundle_src.yaml")
    target = tmp_path / "signatures.yaml"
    target.write_text("[]\n", encoding="utf-8")
    puller = Puller("http://feed/bundle.json", transport=httpx2.ASGITransport(app=build_feed_app(src)))
    return src, target, puller


async def test_published_signature_is_pulled_and_blocks(env):
    src, target, puller = env
    publish(src, "id=evil_token,pattern=zz-evil-[0-9]+,action=block,tags=TEST-1;TEST-2")
    assert await puller.pull(target)
    assert "evil_token" in target.read_text(encoding="utf-8")
    assert puller.state["last_error"] is None and puller.state["version"] >= 2
    v = scan('{"q": "zz-evil-42"}', "tool_args", {"signatures": str(target)})
    assert v.action == "block" and any(r.rule == "sig.evil_token" for r in v.reasons)
    # seeded supply-chain signatures arrive too
    v = scan('{"code": "AutoModel.from_pretrained(x, trust_remote_code=True)"}', "tool_args", {"signatures": str(target)})
    assert v.action == "block"


async def test_tampered_bundle_rejected(env):
    src, target, puller = env
    b = bundle(src)
    b["signatures"] = [{"id": "noop", "pattern": "a^", "action": "allow"}]  # MITM swaps the rules, keeps the sig
    puller.transport = httpx2.MockTransport(lambda req: httpx2.Response(200, json=b))
    before = target.read_bytes()
    assert not await puller.pull(target)
    assert target.read_bytes() == before
    assert "signature" in puller.state["last_error"]


async def test_stale_version_not_rewritten(env):
    src, target, puller = env
    assert await puller.pull(target)
    mtime = target.stat().st_mtime_ns
    assert not await puller.pull(target)  # same version again
    assert target.stat().st_mtime_ns == mtime and puller.state["last_error"] is None
    # a fresh puller (gateway restart) reads the version stamped in the file
    p2 = Puller("http://feed/bundle.json", transport=puller.transport)
    assert not await p2.pull(target) and target.stat().st_mtime_ns == mtime


@pytest.mark.parametrize("text,hit", [
    ("cos\nsystem\n(S'id'\ntR.", True), ('{"blob": "c__builtin__\neval\n"}', True), ("csubprocess\ncheck_output", True),
    ("m = torch.load('w.pt')", True), ("m = torch.load('w.pt', weights_only=True)", False),
    ("from_pretrained('x', trust_remote_code=True)", True),
    ("yaml.load(f)", True), ("yaml.load(f, Loader=yaml.SafeLoader)", False), ("yaml.safe_load(f)", False),
    ("chain = PALChain.from_math_prompt(llm)", True), ("tools=[PythonREPLTool()]", True), ("the cos of x", False),
])
def test_seed_supply_chain_signatures(tmp_path, text, hit):
    import yaml
    p = tmp_path / "s.yaml"
    p.write_text(yaml.safe_dump(yaml.safe_load(SEED.read_text(encoding="utf-8"))["signatures"]), encoding="utf-8")
    v = scan(text, "tool_args", {"signatures": str(p)})
    assert any(r.rule.startswith("sig.") for r in v.reasons) == hit, v.reasons


async def test_gateway_healthz_reports_feed_and_policy_validates_it():
    import copy

    from tollgate.gateway import build_app
    from tollgate.gateway.policy import PolicyHolder, load_policy, validate
    data = copy.deepcopy(load_policy().data)
    data["feed"] = {"url": "http://127.0.0.1:8090/bundle.json", "interval_s": 10}
    app = build_app(PolicyHolder(validate(data)))
    async with httpx2.AsyncClient(transport=httpx2.ASGITransport(app=app), base_url="http://t") as c:
        feed = (await c.get("/healthz")).json()["feed"]
    assert set(feed) == {"url", "version", "last_pull", "last_error"}
    data["feed"] = {"url": 5}
    with pytest.raises(ValueError, match="feed"):
        validate(data)
