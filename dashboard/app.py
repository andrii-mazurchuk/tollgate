"""Tollgate dashboard (AC14). Read only: audit JSONL + eval.json + the gateway's GET endpoints.

    uv run streamlit run dashboard/app.py
"""
import json
import os
import urllib.request
from pathlib import Path

import pandas as pd
import streamlit as st

import data  # dashboard/data.py; streamlit puts the script dir on sys.path

ROOT = Path(__file__).resolve().parents[1]
AUDIT = Path(os.environ.get("TOLLGATE_AUDIT") or ROOT / "audit" / "events.jsonl")
EVAL = ROOT / "audit" / "eval.json"
URL = os.environ.get("TOLLGATE_URL", "http://127.0.0.1:8080").rstrip("/")
WINDOWS = {"15 min": 15, "1 h": 60, "24 h": 1440, "all": None}

st.set_page_config(page_title="Tollgate", layout="wide")


def live(path: str):
    """GET a gateway JSON endpoint; None when the gateway is down."""
    try:
        with urllib.request.urlopen(URL + path, timeout=0.5) as r:
            return json.load(r)
    except Exception:
        return None


def load_eval():
    try:
        return json.loads(EVAL.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None


with st.sidebar:
    st.header("Filters")
    window = st.selectbox("Time window", list(WINDOWS), index=3)
    roles = st.multiselect("Role", sorted({str(e.get("role")) for e in data.load_events(AUDIT)}))
    doors = st.multiselect("Door", ["tool", "model"])
    verdicts = st.multiselect("Verdict", list(data.ACTIONS))
    st.caption(f"audit: `{AUDIT}`  \ngateway: `{URL}`")


@st.fragment(run_every=2)
def page():
    all_events = data.load_events(AUDIT)
    events = data.filter_events(all_events, roles, doors, verdicts, WINDOWS[window])
    health, taint, budget = live("/healthz"), live("/admin/taint"), live("/admin/budget")
    ev_json = load_eval()

    # 1. header strip
    pol = (health or {}).get("policy") or {}
    if health is None:
        st.warning("Gateway offline: showing the audit file only (no live taint or budget state).")
    if pol.get("last_error"):
        e = pol["last_error"]
        st.error(f"Policy reload REJECTED at {e.get('at')}: {e.get('message')}. Still enforcing {pol.get('version')}.")
    c = st.columns(4)
    version = pol.get("version") or (all_events[-1].get("policy_version") if all_events else None)
    c[0].metric("Policy version", version or "-", help=f"loaded_at {pol.get('loaded_at', '-')}")
    c[1].metric("Loaded at (UTC)", (pol.get("loaded_at") or "-").partition("T")[2].rstrip("Z") or "-")
    c[2].metric("Posture score", f"{ev_json['posture']:.3f}" if ev_json else "-")
    c[3].metric("Events, last 15 min", len(data.since(all_events, 15)))

    # 2. verdict tiles + series
    counts = data.counts_by_action(events)
    for col, (a, n) in zip(st.columns(4), counts.items()):
        col.metric(a.upper(), n)
    series = data.series_by_action(events)
    if series:
        st.bar_chart(pd.DataFrame(series).set_index("t"), color=["#2e7d32", "#f9a825", "#6a1b9a", "#c62828"],
                     height=220)
    c = st.columns(2)
    c[0].caption("By door")
    c[0].bar_chart(pd.Series(data.counts_by(events, "door"), name="events"), horizontal=True, height=150)
    c[1].caption("By scan point")
    c[1].bar_chart(pd.Series(data.counts_by(events, "scan_point"), name="events"), horizontal=True, height=150)

    # 3. top rules  /  5. budgets
    c = st.columns(2)
    with c[0]:
        st.subheader("Top rules")
        top = data.top_rules(events)
        if top:
            df = pd.DataFrame(top)
            df["rule"] = df["rule"] + " (t" + df["tier"].astype(str) + ")"
            st.bar_chart(df.set_index("rule")["count"], horizontal=True, height=300)
        else:
            st.caption("no reasons yet")
    with c[1]:
        st.subheader("Budget burn (today)")
        b = budget if budget is not None else data.budget_from_events(all_events)
        st.caption("live from /admin/budget" if budget is not None else "from audit tokens (gateway offline)")
        for role, u in b.items():
            lim = u.get("limit")
            st.progress(min(u["used"] / lim, 1.0) if lim else 0.0,
                        text=f"{role}: {u['used']:,} / {lim:,} tokens" if lim else f"{role}: {u['used']:,} (no limit)")

    # 4. tainted sessions
    st.subheader("Tainted sessions")
    st.dataframe(pd.DataFrame(data.taint_table(all_events, taint),
                              columns=["key_id", "tainted", "holds_private", "cause", "last_seen"]),
                 hide_index=True, width="stretch")

    # 6. latency
    st.subheader("Latency (ms)")
    lat = data.latency(events)
    st.dataframe(pd.DataFrame({s: lat[s] for s in data.STAGES}).T, width="content")
    st.caption(f"share of events that ran tier 2: {lat['t2_share']:.1%}" if lat["t2_share"] is not None else "")

    # 7. live feed
    st.subheader("Live feed (last 50)")
    feed = pd.DataFrame(data.feed(events), columns=["ts", "role", "door", "tool", "verdict", "rule", "detail"])
    red = lambda row: ["background-color: #ffcdd2; color: #000"] * len(row) if row["verdict"] == "block" else [""] * len(row)  # noqa: E731
    st.dataframe(feed.style.apply(red, axis=1), hide_index=True, width="stretch")

    # 9. export (filtered)
    c = st.columns(2)
    c[0].download_button("Export JSONL", data.to_jsonl(events), "tollgate_events.jsonl", "application/jsonl")
    c[1].download_button("Export CSV", data.to_csv(events), "tollgate_events.csv", "text/csv")

    # 8. eval panel
    st.subheader("Offline evaluation (`tollgate test`)")
    if not ev_json:
        st.caption("no audit/eval.json yet: run `uv run tollgate test`")
        return
    o = ev_json["overall"]
    st.caption(f"{ev_json['split']}; {ev_json['cases_run']} cases run. Overall held-out: precision {o['precision']}, "
               f"recall {o['recall']}, FPR {o['fpr']}")
    cols = ["n", "precision", "recall", "fpr", "pass_rate"]
    st.dataframe(pd.DataFrame(ev_json["sources"]).T[cols], width="stretch")
    inj = ev_json["controls"].get("injection") or {}
    c = st.columns(3)
    c[0].metric("Injection recall (held-out)", inj.get("recall"))
    c[1].metric("Injection FPR (held-out)", inj.get("fpr"))
    c[2].metric("Posture", ev_json["posture"])
    ctl = pd.DataFrame(ev_json["controls"]).T
    st.dataframe(ctl[[k for k in ("weight", "enabled", "n", "pass_rate", "posture_basis", "posture_pass_rate")
                      if k in ctl]], width="stretch")
    st.caption("posture_basis 'full corpus': the held-out split has n < 10 cases for that control, so its posture "
               "uses the full corpus pass rate instead.")
    a = ev_json["ablation"]
    st.caption("AC9 ablation: recall with and without normalisation")
    st.dataframe(pd.DataFrame({"plain": [a["plain_on"], a["plain_off"]],
                               "obfuscated": [a["obfuscated_on"], a["obfuscated_off"]]},
                              index=["normalise on", "normalise off"]), width="content")


st.title("Tollgate")
page()
