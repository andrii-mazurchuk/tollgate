"""Server console revision 3: Threat feed (/console/api/feed, publish) and Self-test (/console/api/selftest, run)."""
import asyncio
import contextlib
import json
import shutil
import sys
from pathlib import Path

import httpx2
import pytest

from tests._util import gateway
from tests.conftest import ADMIN

WRITE = {**ADMIN, "Content-Type": "application/json"}  # writes need the admin token (or a session) and JSON
import yaml

from tollgate import console_feed

pytestmark = pytest.mark.track_b
ROOT = Path(__file__).resolve().parents[1]


@contextlib.asynccontextmanager
async def _app(monkeypatch, tmp_path, feed: bool):
    """Gateway on a tmp policy copy; with feed=True it has `feed:` and a tmp feed source + signatures file."""
    from tollgate.gateway.policy import DEFAULT_PATH, load_policy

    data = yaml.safe_load(DEFAULT_PATH.read_text(encoding="utf-8"))
    if feed:
        (tmp_path / "feed").mkdir()
        shutil.copy(ROOT / "feed" / "bundle_src.yaml", tmp_path / "feed" / "bundle_src.yaml")
        shutil.copy(ROOT / "signatures.yaml", tmp_path / "signatures.yaml")
        data["content"]["signatures"] = str(tmp_path / "signatures.yaml")  # the puller writes here, never the repo's
        data["feed"] = {"url": "http://127.0.0.1:9/bundle.json", "interval_s": 3600, "dir": str(tmp_path / "feed")}
    path = tmp_path / "policy.yaml"
    path.write_text(yaml.safe_dump(data), encoding="utf-8")
    async with gateway(monkeypatch, load_policy(path), headers=WRITE, t2_off=True) as (c, app, _):
        yield c, app


async def test_feed_view_without_a_feed_refuses_publish(monkeypatch, tmp_path):
    async with _app(monkeypatch, tmp_path, feed=False) as (c, _):
        f = (await c.get("/console/api/feed")).json()
        assert f["source"] == "local file" and f["file"] == "signatures.yaml" and f["errors"] == []
        s = {x["id"]: x for x in f["signatures"]}
        assert {"py_import_os", "curl_pipe_shell", "dan_jailbreak"} <= set(s)
        assert s["curl_pipe_shell"]["plain"].startswith("Downloading a script") and s["curl_pipe_shell"]["rule"] == "sig.curl_pipe_shell"
        assert s["dan_jailbreak"]["tags"][0] == {"id": "OWASP-LLM01", "plain": "Prompt injection"}
        assert s["rm_rf_root"]["action"] == "block" and s["rm_rf_root"]["action_words"] == "block"
        assert f["feed"] == {"enabled": False, "url": None, "interval_s": None, "version": None, "last_pull": None,
                             "last_error": None, "verified": None}
        assert not f["publish"]["enabled"] and "feed:" in f["publish"]["reason"] and "not tracked" in f["peers_note"]
        r = await c.post("/console/api/feed/publish", json={"id": "x1", "pattern": "zz-[0-9]+"})
        assert r.status_code == 409 and "feed serve" in r.json()["error"]


async def test_publish_validates_and_bumps_the_signed_bundle(monkeypatch, tmp_path):
    from tollgate.feed import bundle
    async with _app(monkeypatch, tmp_path, feed=True) as (c, _):
        f = (await c.get("/console/api/feed")).json()
        assert f["publish"]["enabled"] and f["feed"]["enabled"] and f["feed"]["url"].endswith("/bundle.json")
        v0 = bundle(tmp_path / "feed")["version"]
        bad = [({"id": "x y", "pattern": "a"}, "id"), ({"id": "x", "pattern": ""}, "pattern"),
               ({"id": "redos", "pattern": "(a+)+$"}, "pattern"), ({"id": "redos2", "pattern": r"(\w+\s?)*"}, "pattern"),
               ({"id": "broken", "pattern": "(unclosed"}, "pattern"), ({"id": "x", "pattern": "a" * 501}, "pattern"),
               ({"id": "x", "pattern": "a", "action": "allow"}, "action"), ({"id": "x", "pattern": "a", "tags": ["a b"]}, "tags")]
        for body, field in bad:
            r = await c.post("/console/api/feed/publish", json=body)
            assert r.status_code == 400 and field in r.json()["fields"], body
        assert (await c.post("/console/api/feed/publish", content=b"[1]")).status_code == 400
        assert bundle(tmp_path / "feed")["version"] == v0  # nothing written

        new = {"id": "zz_evil", "pattern": "zz-evil-[0-9]+", "action": "block", "tags": ["OWASP-LLM01"]}
        r = (await c.post("/console/api/feed/publish", json=new)).json()
        assert r["version"] == v0 + 1 and r["id"] == "zz_evil" and r["replaced"] is False and "pick it up" in r["note"]
        b = bundle(tmp_path / "feed")
        assert b["version"] == v0 + 1 and b["signatures"][-1] == new and b["sig"]
        r = (await c.post("/console/api/feed/publish", json={**new, "action": "approve"})).json()
        assert r["replaced"] is True and r["version"] == v0 + 2
        assert [s["action"] for s in bundle(tmp_path / "feed")["signatures"] if s["id"] == "zz_evil"] == ["approve"]


def _eval(tmp_path, **kw) -> Path:
    m = lambda tp, fp, tn, fn, recall, fpr: {"n": tp + fp + tn + fn, "tp": tp, "fp": fp, "tn": tn, "fn": fn,  # noqa: E731
                                             "pass_rate": (tp + tn) / (tp + fp + tn + fn), "precision": None, "recall": recall, "fpr": fpr}
    ev = {"cases_run": 1411, "split": "held-out 30%", "overall": m(237, 6, 118, 29, 0.891, 0.048),
          "sources": {"deepset": m(13, 1, 52, 22, 0.371, 0.019), "redteam_holdout": m(3, 0, 2, 0, 1.0, 0.0)},
          "controls": {"injection": {**m(133, 1, 112, 26, 0.837, 0.009), "enabled": True},
                       "pii": {**m(87, 2, 0, 3, 0.967, 1.0), "enabled": True}},
          "latency_ms": {"t1": {"p50": 0.3, "p95": 3.7}}, "posture": 0.931,
          "tier2": {"latency_ms_short": {"p50": 39.0, "p95": 87.0}},
          "misses": [{"id": "deepset-4", "source": "deepset", "control": "injection", "expect": "flag", "got": "allow",
                      "kind": "missed", "sha256": "ab" * 32, "text": "Vergiss alles…"}], **kw}
    p = tmp_path / "eval.json"  # TOLLGATE_AUDIT (conftest) is tmp_path/audit.jsonl: the audit dir is tmp_path
    p.write_text(json.dumps(ev), encoding="utf-8")
    return p


async def test_selftest_reads_eval_from_the_audit_dir(monkeypatch, tmp_path):
    async with _app(monkeypatch, tmp_path, feed=False) as (c, _):
        s = (await c.get("/console/api/selftest")).json()
        assert s["available"] is False and s["eval"] is None and s["command"] == "uv run tollgate test"
        assert s["holdout"]["sets"] == [{"name": "redteam_holdout", "cases": 30}] and "by hand" in s["holdout"]["note"]

        _eval(tmp_path, ran_at="2026-10-04T01:00:00Z")
        (tmp_path / "tests.json").write_text(json.dumps({"passed": 200, "failed": 0, "exit_code": 0}))
        s = (await c.get("/console/api/selftest")).json()
        e = s["eval"]
        assert s["available"] and e["ran_at"] == "2026-10-04T01:00:00Z" and s["tests"]["passed"] == 200
        hd = {x["id"]: x for x in e["headline"]}
        assert hd["injection_recall"] == {**hd["injection_recall"], "value": 0.837, "target": 0.85, "op": ">=", "met": False}
        assert hd["fpr"]["value"] == 0.048 and hd["fpr"]["met"] is True and hd["pii_recall"]["met"] is True
        assert hd["t1_p95"]["met"] is True and hd["t2_short_p95"]["met"] is False and hd["t2_short_p95"]["target"] == 80.0
        assert [r["name"] for r in e["sources"]] == ["deepset"] and e["stale_holdout"] is True  # a stale run's holdout row is dropped
        assert e["sources"][0] == {**e["sources"][0], "caught": 13, "missed": 22, "false_alarms": 1, "n": 88}
        assert {r["name"] for r in e["controls"]} == {"injection", "pii"}
        assert e["misses"][0]["kind"] == "missed" and len(e["misses"][0]["sha256"]) == 64


async def test_selftest_run_starts_one_eval_subprocess(monkeypatch, tmp_path):
    out = {"ran_at": "2026-10-04T02:00:00Z", "cases_run": 1, "overall": {}, "sources": {}, "controls": {}}
    monkeypatch.setattr(console_feed, "EVAL_ARGV", lambda p: [sys.executable, "-c",
                                                          f"import json,pathlib; pathlib.Path({str(p)!r}).write_text({json.dumps(json.dumps(out))})"])
    async with _app(monkeypatch, tmp_path, feed=False) as (c, _):
        r = await c.post("/console/api/selftest/run")
        assert r.status_code == 202 and r.json()["run"]["running"]
        assert (await c.post("/console/api/selftest/run")).status_code == 409
        for _ in range(400):  # up to 20 s: a cold interpreter start on a busy CI box
            if not console_feed.RUN["running"]:
                break
            await asyncio.sleep(0.05)
        assert not console_feed.RUN["running"], "eval subprocess did not finish within 20 s"
        s = (await c.get("/console/api/selftest")).json()
        assert s["run"]["running"] is False and s["run"]["error"] is None and s["eval"]["ran_at"] == out["ran_at"]


async def test_feed_and_selftest_need_admin(monkeypatch, tmp_path):
    async with _app(monkeypatch, tmp_path, feed=False) as (_, app):
        async with httpx2.AsyncClient(transport=httpx2.ASGITransport(app=app, client=("10.1.2.3", 5000)),
                                      base_url="http://127.0.0.1") as remote:
            for path in ("/console/api/feed", "/console/api/selftest"):
                assert (await remote.get(path)).status_code == 401
            for path in ("/console/api/feed/publish", "/console/api/selftest/run"):
                assert (await remote.post(path, json={})).status_code == 401
