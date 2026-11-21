"""Detection engine: enrichment attachment, rule execution, correlation and summary."""

from collections import Counter

from agent.alerts import build_alert, finalize, now_str
from agent.persistence_rules import analyze_startup, analyze_tasks
from agent.process_rules import ProcessIndex, allowed_names, analyze_processes, trust_label
from agent.rules_data import RULE_CATALOG, SEVERITY_ORDER
from agent.service_rules import analyze_services


def collect_paths(snapshot):
    paths = set()
    for key in ("processes",):
        paths.update(p["path"] for p in snapshot.get(key, []) if p.get("path"))
    for key in ("services", "startup", "tasks"):
        paths.update(i["exe"] for i in snapshot.get(key, []) if i.get("exe"))
    return paths


def attach_enrichment(snapshot, enrichment):
    """Copy hash / signature data onto every item that references an executable."""
    def apply(item, path):
        info = enrichment.get((path or "").lower())
        if info:
            item["sha256"] = info.get("sha256")
            item["sig_status"] = info.get("sig_status")
            item["signer"] = info.get("signer")

    for proc in snapshot.get("processes", []):
        apply(proc, proc.get("path"))
    for key in ("services", "startup", "tasks"):
        for item in snapshot.get(key, []):
            apply(item, item.get("exe"))


def label_processes(snapshot, custom):
    allowed = allowed_names(custom)
    for proc in snapshot.get("processes", []):
        proc["trust"] = trust_label(proc, allowed)


def run_detection(snapshot, baseline, custom, ioc_hashes):
    """Run every rule set. `baseline` may be None on a first run (drift rules skipped)."""
    label_processes(snapshot, custom)
    alerts = []
    alerts += analyze_processes(snapshot.get("processes", []), custom, ioc_hashes)
    alerts += analyze_services(snapshot.get("services", []),
                               baseline["services"] if baseline else None,
                               snapshot.get("service_acl"), custom)
    alerts += analyze_startup(snapshot.get("startup", []), baseline["startup"] if baseline else None)
    alerts += analyze_tasks(snapshot.get("tasks", []), baseline["tasks"] if baseline else None)
    alerts += chain_correlation(snapshot.get("processes", []), alerts)
    return finalize(alerts, custom.get("suppressions"))


def chain_correlation(processes, alerts):
    """Escalate descendants of a process that already tripped a parent-child rule.

    Example: WINWORD -> cmd (PROC-001) -> powershell -enc (PROC-008) is one attack, not two.
    """
    seeds = {a["pid"] for a in alerts if a["rule_id"] == "PROC-001" and a.get("pid") is not None}
    if not seeds:
        return []
    index = ProcessIndex(processes)
    extra, done = [], set()
    for alert in alerts:
        if not alert["rule_id"].startswith("PROC") or alert["rule_id"] == "PROC-001" or alert["score"] < 4:
            continue
        proc = index.by_pid.get(alert.get("pid"))
        if not proc or proc["pid"] in done:
            continue
        ancestor, depth = index.parent_of(proc), 0
        while ancestor and depth < 8:
            if ancestor["pid"] in seeds:
                done.add(proc["pid"])
                extra.append(build_alert(
                    "CORR-001", 10,
                    f"Attack chain: {proc.get('name')} descends from {ancestor.get('name')} "
                    f"which already tripped a suspicious parent-child rule.",
                    entity=alert["entity"], name=proc.get("name"), pid=proc["pid"], ppid=proc.get("ppid"),
                    path=proc.get("path"), username=proc.get("username"),
                    evidence={"lineage": index.lineage(proc), "seed_pid": ancestor["pid"], "trigger": alert["rule_id"]}))
                break
            ancestor, depth = index.parent_of(ancestor), depth + 1
    return extra


def build_summary(snapshot, alerts, *, mode, suppressed=0, duration=0.0, is_admin=False,
                  baseline_status="n/a", signatures_checked=False):
    from agent.config import VERSION

    severity = Counter(a["severity"] for a in alerts)
    by_type = Counter(a["alert_type"] for a in alerts)
    by_rule = Counter(a["rule_id"] for a in alerts)
    techniques = Counter((a["mitre_id"], a["mitre_technique"], a["mitre_tactic"]) for a in alerts if a["mitre_id"] != "-")

    risk = {}
    for alert in alerts:
        if alert["rule_id"] == "CORR-001":
            continue
        entry = risk.setdefault(alert["entity"], {"entity": alert["entity"], "name": alert.get("name"),
                                                 "pid": alert.get("pid"), "score": 0, "rules": []})
        entry["score"] += alert["score"]
        entry["rules"].append(alert["rule_id"])
    risky = sorted(risk.values(), key=lambda r: -r["score"])[:10]
    for item in risky:
        item["rules"] = sorted(set(item["rules"]))

    trust = Counter(p.get("trust", "Unverified") for p in snapshot.get("processes", []))
    return {
        "timestamp": now_str(),
        "version": VERSION,
        "mode": mode,
        "is_admin": is_admin,
        "scan_duration_seconds": round(duration, 2),
        "baseline_status": baseline_status,
        "signatures_checked": signatures_checked,
        "processes_detected": len(snapshot.get("processes", [])),
        "services_detected": len(snapshot.get("services", [])),
        "startup_entries_detected": len(snapshot.get("startup", [])),
        "scheduled_tasks_detected": len(snapshot.get("tasks", [])),
        "process_relationship_alerts": by_type.get("PROCESS_RELATIONSHIP", 0),
        "service_alerts": by_type.get("SERVICE", 0),
        "unauthorized_process_alerts": by_type.get("UNAUTHORIZED_PROCESS", 0),
        "masquerading_alerts": by_type.get("MASQUERADING", 0),
        "command_line_alerts": by_type.get("COMMAND_LINE", 0),
        "persistence_alerts": by_type.get("PERSISTENCE", 0),
        "correlation_alerts": by_type.get("CORRELATION", 0),
        "total_alerts": len(alerts),
        "critical_alerts": severity.get("CRITICAL", 0),
        "high_alerts": severity.get("HIGH", 0),
        "medium_alerts": severity.get("MEDIUM", 0),
        "low_alerts": severity.get("LOW", 0),
        "suppressed_alerts": suppressed,
        "alerts_by_type": dict(by_type),
        "top_rules": [{"rule_id": r, "name": RULE_CATALOG[r]["name"], "count": c} for r, c in by_rule.most_common(10)],
        "mitre_techniques": [{"id": t[0], "technique": t[1], "tactic": t[2], "count": c}
                             for t, c in techniques.most_common()],
        "risky_entities": risky,
        "process_trust": dict(trust),
        "rules_loaded": len(RULE_CATALOG),
        "severity_order": SEVERITY_ORDER,
    }
