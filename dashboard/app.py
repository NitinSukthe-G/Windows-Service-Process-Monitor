"""Streamlit dashboard for the Windows Service & Process Monitoring Agent.

Run:  streamlit run dashboard/app.py
Reads the report files written by `python agent/monitor.py` (reports/) or by the safe
synthetic scenario `python agent/monitor.py --demo` (reports/demo/).
"""

import json
import sys
from collections import defaultdict
from pathlib import Path

import altair as alt
import pandas as pd
import streamlit as st

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from agent.rules_data import RULE_CATALOG, SEVERITY_ORDER  # noqa: E402

SOURCES = {"Live scan (this machine)": ROOT / "reports", "Demo attack scenario (synthetic)": ROOT / "reports" / "demo"}
SEV_COLORS = {"CRITICAL": "#b42318", "HIGH": "#e8590c", "MEDIUM": "#d99a00", "LOW": "#2f9e44"}
SEV_ICON = {"CRITICAL": "🟥", "HIGH": "🟧", "MEDIUM": "🟨", "LOW": "🟩"}

st.set_page_config(page_title="Windows Service & Process Monitor", page_icon="🛡️", layout="wide")

st.markdown("""
<style>
.block-container{padding-top:1.4rem}
.hero{background:linear-gradient(120deg,#0f2742,#1b4b7a);color:#fff;padding:22px 28px;border-radius:12px;margin-bottom:18px}
.hero h1{margin:0;font-size:28px;color:#fff} .hero p{margin:4px 0 0;opacity:.85}
.pill{display:inline-block;padding:2px 10px;border-radius:12px;font-size:12px;font-weight:700;color:#fff}
[data-testid="stMetricValue"]{font-size:30px}
</style>""", unsafe_allow_html=True)


# ---------------------------------------------------------------------------
# Data loading
# ---------------------------------------------------------------------------

def _mtime(path):
    try:
        return path.stat().st_mtime
    except OSError:
        return 0


@st.cache_data(show_spinner=False)
def load_json(path_str, mtime):
    try:
        return json.loads(Path(path_str).read_text(encoding="utf-8-sig"))
    except (OSError, ValueError):
        return {}


@st.cache_data(show_spinner=False)
def load_csv(path_str, mtime):
    try:
        return pd.read_csv(path_str, dtype=str, keep_default_na=False)
    except (OSError, ValueError, pd.errors.EmptyDataError):
        return pd.DataFrame()


@st.cache_data(show_spinner=False)
def load_history(path_str, mtime):
    rows = []
    try:
        for line in Path(path_str).read_text(encoding="utf-8").splitlines():
            if line.strip():
                rows.append(json.loads(line))
    except (OSError, ValueError):
        pass
    return pd.DataFrame(rows)


def get(folder, name):
    path = folder / name
    return str(path), _mtime(path)


# ---------------------------------------------------------------------------
# Sidebar
# ---------------------------------------------------------------------------

available = {label: folder for label, folder in SOURCES.items() if (folder / "alerts.json").exists()}
st.sidebar.title("🛡️ Monitor")
if not available:
    st.error("No report data found. Run `python agent/monitor.py` or `python agent/monitor.py --demo` first.")
    st.stop()

source_label = st.sidebar.radio("Data source", list(available), index=0)
folder = available[source_label]

summary = load_json(*get(folder, "monitoring_summary.json"))
alerts_raw = load_json(*get(folder, "alerts.json")).get("alerts", [])
processes = load_csv(*get(folder, "process_report.csv"))
services = load_csv(*get(folder, "service_report.csv"))
startup = load_csv(*get(folder, "startup_report.csv"))
tasks = load_csv(*get(folder, "scheduled_task_report.csv"))
history = load_history(*get(folder, "scan_history.jsonl"))

alerts = pd.DataFrame([{
    "Severity": a.get("severity"), "Score": a.get("score"), "Rule": a.get("rule_id"), "Rule name": a.get("rule_name"),
    "Type": a.get("alert_type"), "Entity": a.get("name"), "PID": a.get("pid"), "Reason": a.get("reason"),
    "MITRE": a.get("mitre_id"), "Tactic": a.get("mitre_tactic"), "Technique": a.get("mitre_technique"),
    "Path": a.get("path"), "Time": a.get("timestamp"),
} for a in alerts_raw])

st.sidebar.markdown("---")
st.sidebar.subheader("Alert filters")
sev_filter = st.sidebar.multiselect("Severity", SEVERITY_ORDER, default=SEVERITY_ORDER)
type_options = sorted(alerts["Type"].dropna().unique()) if not alerts.empty else []
type_filter = st.sidebar.multiselect("Alert type", type_options, default=type_options)
search = st.sidebar.text_input("Search alerts", placeholder="entity, rule, reason...")
st.sidebar.markdown("---")
st.sidebar.caption(f"Report folder: `{folder.relative_to(ROOT)}`")
if st.sidebar.button("🔄 Reload data"):
    st.cache_data.clear()
    st.rerun()

filtered = alerts.copy()
if not filtered.empty:
    filtered = filtered[filtered["Severity"].isin(sev_filter) & filtered["Type"].isin(type_filter)]
    if search:
        needle = search.lower()
        mask = filtered.apply(lambda row: needle in " ".join(str(v).lower() for v in row.values), axis=1)
        filtered = filtered[mask]

# ---------------------------------------------------------------------------
# Header + KPIs
# ---------------------------------------------------------------------------

mode = summary.get("mode", "live")
st.markdown(
    f'<div class="hero"><h1>Windows Service &amp; Process Monitoring Agent</h1>'
    f'<p>Endpoint detection dashboard · last scan <b>{summary.get("timestamp", "n/a")}</b> · '
    f'mode <b>{mode}</b> · agent v{summary.get("version", "?")} · {summary.get("rules_loaded", len(RULE_CATALOG))} detection rules</p></div>',
    unsafe_allow_html=True)
if mode == "demo":
    st.info("**Demo mode** – synthetic attack scenarios fed through the real detection engine. No malware was executed.")

cols = st.columns(6)
cols[0].metric("Processes", summary.get("processes_detected", 0))
cols[1].metric("Services", summary.get("services_detected", 0))
cols[2].metric("Total alerts", summary.get("total_alerts", 0))
cols[3].metric("🟥 Critical", summary.get("critical_alerts", 0))
cols[4].metric("🟧 High", summary.get("high_alerts", 0))
cols[5].metric("🟨 Medium / 🟩 Low", f'{summary.get("medium_alerts", 0)} / {summary.get("low_alerts", 0)}')

tabs = st.tabs(["📊 Overview", "🚨 Alerts", "🌳 Processes", "⚙️ Services", "🔁 Persistence", "🎯 MITRE & Rules", "ℹ️ About"])

# ---------------------------------------------------------------------------
# Overview
# ---------------------------------------------------------------------------

with tabs[0]:
    left, right = st.columns(2)
    sev_df = pd.DataFrame({"Severity": SEVERITY_ORDER,
                           "Alerts": [summary.get(f"{s.lower()}_alerts", 0) for s in SEVERITY_ORDER]})
    with left:
        st.subheader("Alerts by severity")
        st.altair_chart(alt.Chart(sev_df).mark_bar(cornerRadiusTopRight=4, cornerRadiusBottomRight=4).encode(
            y=alt.Y("Severity:N", sort=SEVERITY_ORDER, title=None), x=alt.X("Alerts:Q", title=None),
            color=alt.Color("Severity:N", scale=alt.Scale(domain=SEVERITY_ORDER, range=[SEV_COLORS[s] for s in SEVERITY_ORDER]), legend=None),
            tooltip=["Severity", "Alerts"]).properties(height=190), width="stretch")
    with right:
        st.subheader("Alerts by type")
        by_type = pd.DataFrame(sorted(summary.get("alerts_by_type", {}).items(), key=lambda kv: -kv[1]), columns=["Type", "Alerts"])
        if by_type.empty:
            st.success("No alerts – nothing to chart.")
        else:
            st.altair_chart(alt.Chart(by_type).mark_bar(cornerRadiusTopRight=4, cornerRadiusBottomRight=4, color="#38bdf8").encode(
                y=alt.Y("Type:N", sort="-x", title=None), x=alt.X("Alerts:Q", title=None), tooltip=["Type", "Alerts"]).properties(height=190),
                width="stretch")

    st.subheader("Highest-risk entities")
    risky = pd.DataFrame(summary.get("risky_entities", []))
    if risky.empty:
        st.success("No risky entities.")
    else:
        risky["rules"] = risky["rules"].apply(lambda r: ", ".join(r))
        st.dataframe(risky[["name", "pid", "score", "rules"]].rename(columns={"name": "Entity", "pid": "PID", "score": "Risk score", "rules": "Rules"}),
                     width="stretch", hide_index=True)

    trust = summary.get("process_trust", {})
    if trust:
        st.subheader("Process trust posture")
        st.altair_chart(alt.Chart(pd.DataFrame(list(trust.items()), columns=["Trust", "Processes"])).mark_arc(innerRadius=55).encode(
            theta="Processes:Q", color=alt.Color("Trust:N", legend=alt.Legend(orient="right")), tooltip=["Trust", "Processes"]).properties(height=230),
            width="stretch")

    if len(history) > 1:
        st.subheader("Alert trend across scans")
        trend = history.melt(id_vars="timestamp", value_vars=["critical_alerts", "high_alerts", "medium_alerts", "low_alerts"])
        st.altair_chart(alt.Chart(trend).mark_line(point=True).encode(
            x=alt.X("timestamp:N", title=None), y=alt.Y("value:Q", title="Alerts"), color="variable:N").properties(height=220),
            width="stretch")

# ---------------------------------------------------------------------------
# Alerts
# ---------------------------------------------------------------------------

with tabs[1]:
    st.subheader(f"Security alerts ({len(filtered)} shown of {len(alerts)})")
    if filtered.empty:
        st.success("No alerts match the current filters.")
    else:
        st.dataframe(filtered[["Severity", "Score", "Rule", "Entity", "PID", "Reason", "MITRE", "Tactic", "Time"]],
                     width="stretch", hide_index=True, height=360)
        st.download_button("⬇️ Download filtered alerts (CSV)", filtered.to_csv(index=False).encode("utf-8"), "alerts_filtered.csv", "text/csv")

        st.subheader("Investigation drill-down")
        by_key = {a["alert_id"]: a for a in alerts_raw}
        wanted = set()
        for _, row in filtered.iterrows():
            for a in alerts_raw:
                if a.get("rule_id") == row["Rule"] and a.get("name") == row["Entity"] and a.get("reason") == row["Reason"]:
                    wanted.add(a["alert_id"])
                    break
        for alert_id in [a["alert_id"] for a in alerts_raw if a["alert_id"] in wanted][:40]:
            a = by_key[alert_id]
            with st.expander(f'{SEV_ICON.get(a["severity"], "")} {a["severity"]} · {a["rule_id"]} · {a.get("name")}'
                             f'{" (PID " + str(a["pid"]) + ")" if a.get("pid") is not None else ""} — {a["rule_name"]}'):
                st.markdown(f'**Why it fired:** {a["reason"]}')
                st.markdown(f'**MITRE ATT&CK:** `{a["mitre_id"]}` {a["mitre_technique"]} — *{a["mitre_tactic"]}*')
                st.markdown(f'**Recommended response:** {a["recommendation"]}')
                st.json(a.get("evidence") or {}, expanded=False)

# ---------------------------------------------------------------------------
# Processes
# ---------------------------------------------------------------------------

with tabs[2]:
    st.subheader("Process tree (parent → child)")
    if processes.empty:
        st.info("No process data.")
    else:
        flagged = defaultdict(str)
        for a in alerts_raw:
            if a.get("pid") is not None and a["rule_id"] != "CORR-001":
                rank = SEVERITY_ORDER.index(a["severity"])
                current = flagged.get(str(a["pid"]))
                if current is None or rank < SEVERITY_ORDER.index(current):
                    flagged[str(a["pid"])] = a["severity"]
        rows = {r["pid"]: r for r in processes.to_dict("records")}
        children = defaultdict(list)
        for pid, row in rows.items():
            parent = rows.get(row["ppid"])
            valid = parent is not None and row["ppid"] != pid and not (parent.get("started") and row.get("started") and parent["started"] > row["started"])
            children[row["ppid"] if valid else "ROOT"].append(pid)

        lines = []

        def walk(pid, prefix="", last=True, depth=0):
            row = rows[pid]
            mark = SEV_ICON.get(flagged.get(pid), "")
            branch = "" if depth == 0 else ("└─ " if last else "├─ ")
            lines.append(f'{prefix}{branch}{row["name"]} ({pid}) {mark}')
            kids = sorted(children.get(pid, []), key=int)
            for i, kid in enumerate(kids):
                walk(kid, prefix + ("" if depth == 0 else ("   " if last else "│  ")), i == len(kids) - 1, depth + 1)

        only_flagged = st.checkbox("Show only branches that contain a flagged process", value=len(flagged) > 0)

        def has_flag(pid):
            return pid in flagged or any(has_flag(k) for k in children.get(pid, []))

        for root in sorted(children.get("ROOT", []), key=int):
            if not only_flagged or has_flag(root):
                walk(root)
        st.code("\n".join(lines[:600]) or "No flagged branches.", language=None)
        st.caption("🟥 critical · 🟧 high · 🟨 medium · 🟩 low")

        st.subheader("Process inventory")
        c1, c2 = st.columns([2, 1])
        q = c1.text_input("Search processes", key="psearch", placeholder="name, path, user, command line...")
        trust_opts = sorted(processes["trust"].unique()) if "trust" in processes else []
        trust_sel = c2.multiselect("Trust", trust_opts, default=trust_opts)
        view = processes.copy()
        if "trust" in view:
            view = view[view["trust"].isin(trust_sel)]
        if q:
            view = view[view.apply(lambda r: q.lower() in " ".join(r.astype(str)).lower(), axis=1)]
        shown = [c for c in ("pid", "ppid", "name", "trust", "signer", "username", "path", "cmdline", "started") if c in view]
        st.dataframe(view[shown], width="stretch", hide_index=True, height=380)
        st.caption(f"{len(view)} of {len(processes)} processes")

# ---------------------------------------------------------------------------
# Services
# ---------------------------------------------------------------------------

with tabs[3]:
    svc_alerts = filtered[filtered["Type"] == "SERVICE"] if not filtered.empty else filtered
    st.subheader(f"Flagged services ({len(svc_alerts)})")
    if svc_alerts.empty:
        st.success("No service alerts.")
    else:
        st.dataframe(svc_alerts[["Severity", "Rule", "Entity", "Reason", "MITRE"]], width="stretch", hide_index=True)
    st.subheader("Service inventory")
    if services.empty:
        st.info("No service data.")
    else:
        q = st.text_input("Search services", key="ssearch")
        c1, c2 = st.columns(2)
        states = c1.multiselect("State", sorted(services["state"].unique()), default=sorted(services["state"].unique()))
        modes = c2.multiselect("Start mode", sorted(services["start_mode"].unique()), default=sorted(services["start_mode"].unique()))
        view = services[services["state"].isin(states) & services["start_mode"].isin(modes)]
        if q:
            view = view[view.apply(lambda r: q.lower() in " ".join(r.astype(str)).lower(), axis=1)]
        shown = [c for c in ("name", "display_name", "state", "start_mode", "start_name", "path", "sig_status", "signer") if c in view]
        st.dataframe(view[shown], width="stretch", hide_index=True, height=380)
        st.caption(f"{len(view)} of {len(services)} services")

# ---------------------------------------------------------------------------
# Persistence
# ---------------------------------------------------------------------------

with tabs[4]:
    pers = filtered[filtered["Type"] == "PERSISTENCE"] if not filtered.empty else filtered
    st.subheader(f"Persistence alerts ({len(pers)})")
    if pers.empty:
        st.success("No persistence alerts.")
    else:
        st.dataframe(pers[["Severity", "Rule", "Entity", "Reason", "MITRE"]], width="stretch", hide_index=True)
    st.subheader("Startup entries (Run keys & Startup folders)")
    st.dataframe(startup, width="stretch", hide_index=True) if not startup.empty else st.info("No startup data.")
    st.subheader("Scheduled tasks")
    if tasks.empty:
        st.info("No scheduled-task data.")
    else:
        q = st.text_input("Search tasks", key="tsearch")
        view = tasks if not q else tasks[tasks.apply(lambda r: q.lower() in " ".join(r.astype(str)).lower(), axis=1)]
        st.dataframe(view, width="stretch", hide_index=True, height=320)

# ---------------------------------------------------------------------------
# MITRE & rules
# ---------------------------------------------------------------------------

with tabs[5]:
    st.subheader("MITRE ATT&CK techniques observed")
    techniques = pd.DataFrame(summary.get("mitre_techniques", []))
    if techniques.empty:
        st.success("No ATT&CK techniques were observed in this scan.")
    else:
        st.dataframe(techniques.rename(columns={"id": "Technique", "technique": "Name", "tactic": "Tactic", "count": "Alerts"}),
                     width="stretch", hide_index=True)
    st.subheader(f"Detection rule catalog ({len(RULE_CATALOG)} rules)")
    fired = {r["rule_id"]: r["count"] for r in summary.get("top_rules", [])}
    catalog = pd.DataFrame([{"Rule": rid, "Name": m["name"], "Category": m["alert_type"], "Tactic": m["tactic"],
                             "Technique": m["technique"], "Fired": fired.get(rid, 0), "What it detects": m["description"]}
                            for rid, m in RULE_CATALOG.items()])
    st.dataframe(catalog, width="stretch", hide_index=True, height=420)

# ---------------------------------------------------------------------------
# About / downloads
# ---------------------------------------------------------------------------

with tabs[6]:
    st.subheader("Scan details")
    st.json({k: summary.get(k) for k in ("timestamp", "mode", "version", "is_admin", "scan_duration_seconds", "baseline_status",
                                         "signatures_checked", "suppressed_alerts", "startup_entries_detected", "scheduled_tasks_detected")})
    st.subheader("Downloads")
    d1, d2, d3 = st.columns(3)
    html_path = folder / "detection_report.html"
    if html_path.exists():
        d1.download_button("⬇️ Detection report (HTML)", html_path.read_bytes(), "detection_report.html", "text/html")
    d2.download_button("⬇️ Alerts (JSON)", json.dumps({"alerts": alerts_raw}, indent=2).encode("utf-8"), "alerts.json", "application/json")
    d3.download_button("⬇️ Summary (JSON)", json.dumps(summary, indent=2).encode("utf-8"), "monitoring_summary.json", "application/json")
    st.markdown("""
**How it works** – the agent enumerates processes, services, startup entries and scheduled tasks, enriches executables with
SHA-256 hashes and Authenticode signatures, runs 30+ rules mapped to MITRE ATT&CK, correlates independent signals per entity,
and writes CSV/JSON/HTML reports. Alerts are *indicators for investigation*, not proof of compromise.

Defensive use only · authorised systems only.
""")
