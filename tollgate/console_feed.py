"""Server console, revision 3 (docs/ui-spec.md): the Threat feed and Self-test views' API, mounted under /console/api.

Feed: the signatures in force (the file `content.signatures` points at), the hub's puller state, and publish through
tollgate.feed.add. Self-test: audit/eval.json (+ tests.json, perf.json) from the audit dir; Run starts the eval in a subprocess (about
10 s with the tier 2 score cache warm, minutes cold). The held-out red-team set is never loaded (eval.corpus.load)."""
import asyncio
import json
import os
import re
import sys
from datetime import datetime, timezone
from pathlib import Path

import yaml
from starlette.requests import Request
from starlette.responses import JSONResponse
from starlette.routing import Route

from tollgate import accounts, edge
from tollgate.content import signatures as sigs
from tollgate.feed import _STAMP, SRC, add, check_signatures
from tollgate.util import iso_z, now_z

ROOT = Path(__file__).resolve().parents[1]
FEED_HOWTO = ("Publishing needs a signature feed. Add `feed: {url: http://127.0.0.1:8090/bundle.json, interval_s: 10}` "
              "to policy.yaml (optionally `dir:` for the feed's source folder, default `feed/`) and run "
              "`tollgate feed serve`.")
PEERS_NOTE = "Per-peer feed versions are not tracked: laptops do not report which signature version they run."
EVAL_CMD = "uv run tollgate test"
ACTIONS = ("block", "approve", "redact")  # what a published signature may do (signatures.py also accepts allow)
ID = re.compile(r"^[A-Za-z0-9_]{1,64}$")
TAG = re.compile(r"^[A-Za-z0-9._-]{1,40}$")

# OWASP Top 10 for LLM Applications 2025 and MITRE ATLAS technique names, for the tags in plain words
TAG_WORDS = {
    "OWASP-LLM01": "Prompt injection", "OWASP-LLM02": "Sensitive information disclosure", "OWASP-LLM03": "Supply chain",
    "OWASP-LLM04": "Data and model poisoning", "OWASP-LLM05": "Improper output handling",
    "OWASP-LLM06": "Excessive agency", "OWASP-LLM07": "System prompt leakage",
    "OWASP-LLM08": "Vector and embedding weaknesses", "OWASP-LLM09": "Misinformation",
    "OWASP-LLM10": "Unbounded consumption",
    "ATLAS-AML.T0011": "User execution", "ATLAS-AML.T0048": "External harms", "ATLAS-AML.T0050": "Command and scripting interpreter",
    "ATLAS-AML.T0051": "LLM prompt injection", "ATLAS-AML.T0054": "LLM jailbreak", "ATLAS-AML.T0010": "ML supply chain compromise",
    "unsafe-deserialization": "Unsafe deserialization", "supply-chain": "Supply chain",
}
ADVISORY = ("CVE-", "GHSA-", "PYSEC-")
# ponytail: plain words for the shipped signatures; a published one without an entry here reads from its tags
PLAIN = {
    "py_import_os": "Python code that imports the os module through __import__",
    "py_shell_exec": "Python code that runs a shell command (os.system, subprocess)",
    "pickle_load": "Loading a Python pickle, which can run arbitrary code",
    "curl_pipe_shell": "Downloading a script and piping it straight into a shell",
    "dan_jailbreak": "The \"DAN\" jailbreak prompt",
    "rm_rf_root": "A command that deletes the whole file system (rm -rf /)",
    "pickle_global_exec": "A pickle payload that calls eval, exec or a shell when loaded",
    "torch_load_unsafe": "torch.load without weights_only=True, which can run code from a model file",
    "hf_trust_remote_code": "Loading a Hugging Face model with trust_remote_code=True (runs the repo's code)",
    "yaml_load_unsafe": "yaml.load without SafeLoader, which can build arbitrary Python objects",
    "langchain_palchain": "LangChain tools with known code-execution flaws (PALChain, Python REPL)",
}


def tag_plain(t: str) -> str | None:
    return TAG_WORDS.get(t) or ("Known vulnerability advisory" if t.startswith(ADVISORY) else None)


def _audit_dir() -> Path:
    from tollgate.gateway import audit
    return Path(os.environ.get("TOLLGATE_AUDIT") or audit.DEFAULT_PATH).parent


def _json(p: Path):
    try:
        return json.loads(p.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None


def _mtime(p: Path) -> str | None:
    try:
        return iso_z(datetime.fromtimestamp(p.stat().st_mtime, timezone.utc), "seconds")
    except OSError:
        return None


def plain(e: dict) -> str:
    if e.get("id") in PLAIN:
        return PLAIN[e["id"]]
    words = list(dict.fromkeys(w for w in map(tag_plain, e.get("tags") or []) if w))
    return f"Text matching a known attack pattern ({', '.join(words)})" if words else "Text matching a known attack pattern"


# --- Threat feed ---
def feed_dir(data: dict) -> Path:
    d = Path((data.get("feed") or {}).get("dir") or "feed")
    return d if d.is_absolute() else ROOT / d


def feed_view(data: dict, fs: dict) -> dict:
    rel = (data.get("content") or {}).get("signatures") or "signatures.yaml"
    path = Path(rel) if Path(rel).is_absolute() else ROOT / rel
    try:
        text = path.read_text(encoding="utf-8")
        entries = yaml.safe_load(text) or []
    except (OSError, yaml.YAMLError):
        text, entries = "", []
    stamp = _STAMP.search(text.partition("\n")[0])
    from_feed = stamp is not None  # the puller stamps the first line of every file it writes
    cfg = data.get("feed") or {}
    url = cfg.get("url")
    pub = feed_dir(data)
    can = bool(url) and (pub / SRC).is_file()
    return {
        "file": rel, "source": "threat feed" if from_feed else "local file",
        "file_version": int(stamp.group(1)) if stamp else None, "updated_at": _mtime(path),
        "signatures": [{"id": e.get("id"), "rule": f"sig.{e.get('id')}", "plain": plain(e), "pattern": e.get("pattern"),
                        "action": e.get("action", "block"), "action_words": edge.ACTION_WORDS.get(e.get("action", "block"), e.get("action")),
                        "tags": [{"id": t, "plain": tag_plain(t)} for t in e.get("tags") or []],
                        "source": "threat feed" if from_feed else "local file"}
                       for e in entries if isinstance(e, dict)],
        "errors": sigs.errors(rel),
        "feed": {"enabled": bool(url), "url": url, "interval_s": cfg.get("interval_s", 10) if url else None,
                 "version": fs.get("version"), "last_pull": fs.get("last_pull"), "last_error": fs.get("last_error"),
                 # True: the last pull's HMAC checked out; False: the last pull failed; None: no feed or not pulled yet
                 "verified": None if not (url and fs.get("last_pull")) else fs.get("last_error") is None},
        "publish": {"enabled": can, "dir": str(pub) if can else None,
                    "reason": None if can else FEED_HOWTO if not url else f"No feed source at {pub / SRC}. " + FEED_HOWTO},
        "peers_note": PEERS_NOTE,
    }


def validate(body) -> tuple[dict | None, dict]:
    """(entry, errors by field). Same ReDoS and compile checks as the feed puller, plus the hub's own loader check."""
    if not isinstance(body, dict):
        return None, {"form": "need a JSON object {id, pattern, action, tags}"}
    sid, pat, act, tags = body.get("id"), body.get("pattern"), body.get("action") or "block", body.get("tags") or []
    err = {}
    if not isinstance(sid, str) or not ID.match(sid):
        err["id"] = "Use 1 to 64 letters, digits or underscores."
    if not isinstance(pat, str) or not pat.strip():
        err["pattern"] = "Enter a pattern."
    else:
        try:
            check_signatures([{"id": sid if isinstance(sid, str) else "new", "pattern": pat}])
            if sigs._NESTED.search(pat):  # the hub's loader would skip it: refuse here too
                raise ValueError("nested quantifier (ReDoS risk)")
        except (ValueError, re.error) as e:
            err["pattern"] = str(e).removeprefix(f"signature {sid}: ")
    if act not in ACTIONS:
        err["action"] = f"Pick one of {', '.join(ACTIONS)}."
    if not isinstance(tags, list) or not all(isinstance(t, str) and TAG.match(t) for t in tags):
        err["tags"] = "Tags are short words: letters, digits, dot, dash or underscore (e.g. OWASP-LLM01)."
    return (None if err else {"id": sid, "pattern": pat, "action": act, "tags": tags}), err


# --- Self-test ---
def _target(id_, label, value, op, target, unit, source):
    met = None if value is None else value >= target if op == ">=" else value <= target
    return {"id": id_, "label": label, "value": value, "op": op, "target": target, "unit": unit, "met": met, "source": source}


SOURCE_WORDS = {
    "deepset": "deepset prompt injections", "gandalf": "Gandalf (ignore-instructions attacks)",
    "jackhhao": "Jailbreak classification", "jbb": "JailbreakBench benign prompts", "gretel": "Gretel synthetic finance PII",
    "redteam": "Own red-team cases", "own_poisoned": "Own poisoned tool results", "own_clean": "Own clean instruction-like text",
    "own_pii": "Own PII cases", "own_secrets": "Own secrets cases", "own_signatures": "Own signature cases",
    "own_obf": "Own obfuscated variants", "own_obf_plain": "Own plain originals of the obfuscated",
}
CONTROL_WORDS = {"pii": "Personal data", "secrets": "Secrets", "injection": "Injection", "signatures": "Signatures",
                 "obfuscation": "Obfuscation"}


def _row(name, m, words):
    return {"name": name, "plain": words.get(name, name), "n": m["n"], "caught": m["tp"], "missed": m["fn"],
            "false_alarms": m["fp"], "passed": m["tp"] + m["tn"], "recall": m["recall"], "fpr": m["fpr"],
            "pass_rate": m["pass_rate"]}


def selftest() -> dict:
    d = _audit_dir()
    ev, tests, perf = _json(d / "eval.json"), _json(d / "tests.json"), _json(d / "perf.json")
    holdout = [{"name": p.stem, "cases": sum(1 for line in p.open(encoding="utf-8") if line.strip())}  # counted, never scanned
               for p in sorted((ROOT / "tests" / "corpus").glob("*_holdout.jsonl"))]
    out = {"command": EVAL_CMD, "available": ev is not None,
           "run_note": "Run self-test re-scores the corpus (about 10 s with cached classifier scores). "
                       "The full command also runs the test suite.", "run": RUN,
           "holdout": {"sets": holdout, "note": "Scored once by hand and never re-run: the self-test does not load it, "
                                                "so its result cannot be tuned against."},
           "tests": tests, "eval": None}
    if ev is None:
        return out
    inj, ov = (ev.get("controls") or {}).get("injection") or {}, ev.get("overall") or {}
    t2 = (ev.get("tier2") or {}).get("latency_ms_short") or {}
    heads = [
        _target("injection_recall", "Injection recall", inj.get("recall"), ">=", 0.85, "ratio", "eval, held-out 30%"),
        _target("injection_fpr", "Injection false alarms", inj.get("fpr"), "<=", 0.05, "ratio", "harmless text flagged, held-out 30%"),
        _target("fpr", "False alarms, all checks", ov.get("fpr"), "<=", 0.05, "ratio", "harmless cases flagged, held-out 30%"),
        _target("pii_recall", "Personal-data recall", ((ev.get("controls") or {}).get("pii") or {}).get("recall"), ">=", 0.95,
                "ratio", "eval, held-out 30%"),
        _target("t1_p95", "Tier 1 scan p95", ((ev.get("latency_ms") or {}).get("t1") or {}).get("p95"), "<=", 5.0, "ms", "eval"),
        _target("t2_short_p95", "Classifier p95, short text", t2.get("p95"), "<=", 80.0, "ms", "eval, ≤ 64 tokens"),
    ]
    hub = ((perf or {}).get("ac15") or {}).get("hub")
    if hub:
        heads.append(_target("hub_p95", "Hub checks p95", hub.get("p95"), "<=", hub.get("target", 5.0), "ms", "tollgate perf"))
    srcs = {k: v for k, v in (ev.get("sources") or {}).items() if not k.endswith("_holdout")}  # older runs included it
    out["eval"] = {
        "ran_at": ev.get("ran_at") or _mtime(d / "eval.json"), "duration_s": ev.get("duration_s"), "profile": ev.get("profile"),
        "cases_run": ev.get("cases_run"), "split": ev.get("split"), "posture": ev.get("posture"),
        "headline": heads,
        "sources": [_row(k, m, SOURCE_WORDS) for k, m in srcs.items()],
        "controls": [{**_row(k, c, CONTROL_WORDS), "enabled": c.get("enabled", True)} for k, c in (ev.get("controls") or {}).items()],
        "misses": ev.get("misses"),  # None: the run predates miss recording
        "stale_holdout": len(srcs) != len(ev.get("sources") or {}),
    }
    return out


RUN = {"running": False, "started_at": None, "error": None}
_TASKS: set = set()  # strong refs, so a running eval task is not garbage collected
# argv for one eval run writing to `out`; tests swap it for something cheap
EVAL_ARGV = lambda out: [sys.executable, "-c", f"from tollgate.eval.runner import main; main(out={str(out)!r})"]  # noqa: E731


async def run_eval() -> None:
    """One eval in a subprocess (the eval swaps tier 2 globals; in-process it would cache live traffic)."""
    RUN.update(running=True, started_at=now_z("seconds"), error=None)
    try:
        p = await asyncio.create_subprocess_exec(*EVAL_ARGV(_audit_dir() / "eval.json"), cwd=ROOT,
                                                 stdout=asyncio.subprocess.DEVNULL, stderr=asyncio.subprocess.PIPE)
        _, err = await p.communicate()
        if p.returncode:
            RUN["error"] = err.decode(errors="replace").strip().splitlines()[-1:][0] if err.strip() else f"exit {p.returncode}"
    except Exception as e:  # noqa: BLE001 - reported in the view, never raised into the server
        RUN["error"] = f"{type(e).__name__}: {e}"
    finally:
        RUN["running"] = False


def routes(policy, admin) -> list:
    async def get_feed(request: Request):
        return JSONResponse(feed_view(policy.data, request.app.state.feed.state))

    async def publish(request: Request):
        data = policy.data
        if not (data.get("feed") or {}).get("url"):
            return JSONResponse({"error": FEED_HOWTO}, 409)
        d = feed_dir(data)
        if not (d / SRC).is_file():
            return JSONResponse({"error": f"No feed source at {d / SRC}. " + FEED_HOWTO}, 409)
        try:
            body = await request.json()
        except ValueError:
            body = None
        entry, err = validate(body)
        if err:
            return JSONResponse({"error": "; ".join(f"{k}: {v}" for k, v in err.items()), "fields": err}, 400)
        replaced = any(s.get("id") == entry["id"] for s in (yaml.safe_load((d / SRC).read_text(encoding="utf-8")) or {}).get("signatures") or [])
        version = add(d, entry)
        accounts.log(request.state.who, f"Published signature {entry['id']} (feed v{version})")
        return JSONResponse({"version": version, "id": entry["id"], "replaced": replaced,
                             "note": f"Signed bundle v{version} is live on the feed. Hubs pulling it pick it up within "
                                     f"{(data.get('feed') or {}).get('interval_s', 10)} s."})

    async def get_selftest(_):
        return JSONResponse(selftest())

    async def start_run(request):
        if RUN["running"]:
            return JSONResponse({"error": "a self-test is already running", "run": RUN}, 409)
        accounts.log(request.state.who, "Started a self-test run")
        RUN["running"] = True  # before the task starts: a second click in the same tick gets the 409
        t = asyncio.get_running_loop().create_task(run_eval())
        _TASKS.add(t)
        t.add_done_callback(_TASKS.discard)
        return JSONResponse({"run": RUN}, 202)

    return [Route("/feed", admin(get_feed)), Route("/feed/publish", admin(publish), methods=["POST"]),
            Route("/selftest", admin(get_selftest)), Route("/selftest/run", admin(start_run), methods=["POST"])]
