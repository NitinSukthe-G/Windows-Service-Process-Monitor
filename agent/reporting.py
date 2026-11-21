"""Report writers: CSV, JSON, HTML, history, with privacy redaction."""

import csv
import getpass
import html
import io
import json
import os
import re

from agent.config import MAX_HISTORY_LINES
from agent.rules_data import SEVERITY_ORDER

PROCESS_FIELDS = ["timestamp", "pid", "ppid", "name", "path", "username", "status", "cmdline",
                  "started", "trust", "sig_status", "signer", "sha256"]
SERVICE_FIELDS = ["timestamp", "name", "display_name", "state", "start_mode", "start_name", "path",
                  "exe", "sig_status", "signer", "sha256"]
STARTUP_FIELDS = ["timestamp", "location", "name", "command", "exe", "sig_status", "signer", "sha256"]
TASK_FIELDS = ["timestamp", "task_path", "name", "state", "command", "exe", "user", "sig_status", "signer"]
ALERT_FIELDS = ["timestamp", "severity", "score", "rule_id", "rule_name", "alert_type", "name", "pid", "ppid",
                "path", "username", "reason", "mitre_id", "mitre_tactic", "mitre_technique", "recommendation"]


class Redactor:
    """Replaces the local user name and computer name so reports are safe to publish."""

    def __init__(self, enabled=True):
        self.enabled = enabled
        tokens = []
        if enabled:
            for value, replacement in ((_safe_user(), "%USERNAME%"), (os.environ.get("COMPUTERNAME", ""), "%COMPUTERNAME%")):
                if value and len(value) >= 3:
                    tokens.append((re.compile(re.escape(value), re.IGNORECASE), replacement))
        self.tokens = tokens

    def __call__(self, text):
        for pattern, replacement in self.tokens:
            text = pattern.sub(replacement, text)
        return text


def _safe_user():
    try:
        return getpass.getuser()
    except Exception:
        return os.environ.get("USERNAME", "")


def _write(path, text, redactor):
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w", encoding="utf-8", newline="") as handle:
        handle.write(redactor(text))


def _csv_text(rows, fields):
    buffer = io.StringIO()
    writer = csv.DictWriter(buffer, fieldnames=fields, extrasaction="ignore", lineterminator="\r\n")
    writer.writeheader()
    for row in rows:
        writer.writerow({k: ("" if row.get(k) is None else row.get(k)) for k in fields})
    return buffer.getvalue()


def write_reports(out_dir, snapshot, alerts, summary, redactor):
    """Write every report artefact into out_dir and return {name: path}."""
    out_dir.mkdir(parents=True, exist_ok=True)
    flat_alerts = [dict(a, mitre_technique=a["mitre_technique"]) for a in alerts]
    files = {
        "process_report": out_dir / "process_report.csv",
        "service_report": out_dir / "service_report.csv",
        "startup_report": out_dir / "startup_report.csv",
        "task_report": out_dir / "scheduled_task_report.csv",
        "alerts_csv": out_dir / "alerts.csv",
        "alerts_json": out_dir / "alerts.json",
        "summary": out_dir / "monitoring_summary.json",
        "html": out_dir / "detection_report.html",
    }
    _write(files["process_report"], _csv_text(snapshot.get("processes", []), PROCESS_FIELDS), redactor)
    _write(files["service_report"], _csv_text(snapshot.get("services", []), SERVICE_FIELDS), redactor)
    _write(files["startup_report"], _csv_text(snapshot.get("startup", []), STARTUP_FIELDS), redactor)
    _write(files["task_report"], _csv_text(snapshot.get("tasks", []), TASK_FIELDS), redactor)
    _write(files["alerts_csv"], _csv_text(flat_alerts, ALERT_FIELDS), redactor)
    payload = {"generated_at": summary["timestamp"], "total_alerts": len(alerts), "alerts": alerts}
    _write(files["alerts_json"], json.dumps(payload, indent=2, default=str), redactor)
    _write(files["summary"], json.dumps(summary, indent=2, default=str), redactor)
    _write(files["html"], render_html(summary, alerts, snapshot), redactor)
    return files


def append_history(path, summary, redactor):
    """Append one trend line per scan; keep the file bounded."""
    line = json.dumps({k: summary[k] for k in (
        "timestamp", "mode", "processes_detected", "services_detected", "total_alerts",
        "critical_alerts", "high_alerts", "medium_alerts", "low_alerts")})
    lines = []
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except OSError:
        pass
    lines.append(line)
    _write(path, "\n".join(lines[-MAX_HISTORY_LINES:]) + "\n", redactor)


# ---------------------------------------------------------------------------
# HTML report
# ---------------------------------------------------------------------------

_SEV_COLOR = {"CRITICAL": "#b42318", "HIGH": "#e8590c", "MEDIUM": "#d99a00", "LOW": "#2f7d32"}


def _e(value):
    return html.escape("" if value is None else str(value))


def render_html(summary, alerts, snapshot):
    sev_counts = {s: summary.get(f"{s.lower()}_alerts", 0) for s in SEVERITY_ORDER}
    total = max(1, sum(sev_counts.values()))
    cards = "".join(
        f'<div class="card" style="border-top:4px solid {_SEV_COLOR[s]}"><div class="n">{sev_counts[s]}</div>'
        f'<div class="l">{s.title()}</div></div>' for s in SEVERITY_ORDER)
    bars = "".join(
        f'<div class="bar"><span class="bl">{s.title()}</span><span class="bt"><span style="width:'
        f'{sev_counts[s] * 100 / total:.1f}%;background:{_SEV_COLOR[s]}"></span></span><span class="bv">{sev_counts[s]}</span></div>'
        for s in SEVERITY_ORDER)

    mitre_rows = "".join(
        f"<tr><td>{_e(m['id'])}</td><td>{_e(m['technique'])}</td><td>{_e(m['tactic'])}</td><td>{m['count']}</td></tr>"
        for m in summary.get("mitre_techniques", [])) or '<tr><td colspan="4">No techniques observed.</td></tr>'

    rule_rows = "".join(
        f"<tr><td>{_e(r['rule_id'])}</td><td>{_e(r['name'])}</td><td>{r['count']}</td></tr>"
        for r in summary.get("top_rules", [])) or '<tr><td colspan="3">No rules fired.</td></tr>'

    risky_rows = "".join(
        f"<tr><td>{_e(r['name'])}</td><td>{_e(r['pid'] if r['pid'] is not None else '-')}</td>"
        f"<td>{r['score']}</td><td>{_e(', '.join(r['rules']))}</td></tr>"
        for r in summary.get("risky_entities", [])) or '<tr><td colspan="4">None.</td></tr>'

    alert_rows = []
    for alert in alerts[:150]:
        evidence = alert.get("evidence") or {}
        detail = evidence.get("lineage") or evidence.get("image_path") or evidence.get("command") or ""
        alert_rows.append(
            f'<tr><td><span class="sev" style="background:{_SEV_COLOR[alert["severity"]]}">{alert["severity"]}</span></td>'
            f'<td>{_e(alert["rule_id"])}</td><td><b>{_e(alert.get("name"))}</b>'
            f'{"<br><small>PID " + _e(alert["pid"]) + "</small>" if alert.get("pid") is not None else ""}</td>'
            f'<td>{_e(alert["reason"])}<br><small class="mono">{_e(detail)}</small></td>'
            f'<td>{_e(alert["mitre_id"])}<br><small>{_e(alert["mitre_tactic"])}</small></td></tr>')
    alert_table = "".join(alert_rows) or '<tr><td colspan="5">No alerts - the system looks clean against the loaded rules.</td></tr>'
    more = f"<p class='muted'>Showing 150 of {len(alerts)} alerts. Full list: alerts.csv / alerts.json.</p>" if len(alerts) > 150 else ""

    mode_note = ('<div class="note">DEMO MODE - synthetic attack scenarios injected to demonstrate detections. '
                 'No real malware was executed.</div>') if summary.get("mode") == "demo" else ""

    return f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Windows Service &amp; Process Monitor - Detection Report</title>
<style>
body{{font-family:Segoe UI,Arial,sans-serif;margin:0;background:#f4f6f9;color:#1c2430}}
header{{background:#0f2742;color:#fff;padding:28px 40px}} header h1{{margin:0 0 6px;font-size:26px}}
header p{{margin:0;opacity:.8}} main{{padding:24px 40px;max-width:1280px;margin:auto}}
h2{{margin:32px 0 12px;font-size:19px;border-bottom:2px solid #d5dce6;padding-bottom:6px}}
.cards{{display:flex;gap:16px;flex-wrap:wrap}} .card{{background:#fff;border-radius:8px;padding:16px 24px;min-width:130px;box-shadow:0 1px 3px #0002}}
.card .n{{font-size:34px;font-weight:700}} .card .l{{color:#566}} .meta{{display:flex;gap:16px;flex-wrap:wrap;margin-top:14px}}
.meta div{{background:#fff;border-radius:8px;padding:10px 16px;box-shadow:0 1px 3px #0002}} .meta b{{display:block;font-size:20px}}
.bar{{display:flex;align-items:center;gap:10px;margin:6px 0}} .bl{{width:70px}} .bt{{flex:1;background:#e3e8ef;height:14px;border-radius:7px;overflow:hidden}}
.bt span{{display:block;height:100%}} .bv{{width:40px;text-align:right}}
table{{width:100%;border-collapse:collapse;background:#fff;border-radius:8px;overflow:hidden;box-shadow:0 1px 3px #0002;font-size:14px}}
th{{background:#e8edf4;text-align:left;padding:9px 12px}} td{{padding:9px 12px;border-top:1px solid #e6eaf0;vertical-align:top}}
.sev{{color:#fff;padding:2px 9px;border-radius:10px;font-size:12px;font-weight:700}} small{{color:#667}} .mono{{font-family:Consolas,monospace;word-break:break-all}}
.note{{background:#fff3cd;border:1px solid #ecc94b;padding:10px 16px;border-radius:8px;margin-bottom:16px}} .muted{{color:#667}}
.two{{display:grid;grid-template-columns:1fr 1fr;gap:24px}} @media(max-width:900px){{.two{{grid-template-columns:1fr}}}}
footer{{text-align:center;color:#778;padding:24px;font-size:13px}}
</style></head><body>
<header><h1>Windows Service &amp; Process Monitoring - Detection Report</h1>
<p>Scan {_e(summary['timestamp'])} &middot; mode: {_e(summary['mode'])} &middot; agent v{_e(summary['version'])} &middot; {summary['rules_loaded']} detection rules</p></header>
<main>{mode_note}
<h2>Executive summary</h2>
<div class="cards">{cards}</div>
<div class="meta">
<div><b>{summary['processes_detected']}</b>processes</div><div><b>{summary['services_detected']}</b>services</div>
<div><b>{summary['startup_entries_detected']}</b>startup entries</div><div><b>{summary['scheduled_tasks_detected']}</b>scheduled tasks</div>
<div><b>{summary['total_alerts']}</b>total alerts</div><div><b>{summary['scan_duration_seconds']}s</b>scan time</div>
<div><b>{'Yes' if summary['is_admin'] else 'No'}</b>elevated</div></div>
<h2>Severity distribution</h2>{bars}
<div class="two"><div><h2>Top triggered rules</h2><table><tr><th>Rule</th><th>Name</th><th>Hits</th></tr>{rule_rows}</table></div>
<div><h2>Highest-risk entities</h2><table><tr><th>Name</th><th>PID</th><th>Risk</th><th>Rules</th></tr>{risky_rows}</table></div></div>
<h2>MITRE ATT&amp;CK coverage of findings</h2>
<table><tr><th>Technique</th><th>Name</th><th>Tactic</th><th>Alerts</th></tr>{mitre_rows}</table>
<h2>Alerts (highest risk first)</h2>
<table><tr><th>Severity</th><th>Rule</th><th>Entity</th><th>Details</th><th>MITRE</th></tr>{alert_table}</table>{more}
</main><footer>Generated by the Windows Service &amp; Process Monitoring Agent. Alerts are indicators for investigation, not proof of compromise.</footer>
</body></html>"""
