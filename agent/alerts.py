"""Alert construction, severity scoring, suppression and correlation."""

import hashlib
from collections import defaultdict
from datetime import datetime

from agent.rules_data import RULE_CATALOG, SEVERITY_RANK, TECHNIQUES


def now_str():
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")


def severity_from_score(score):
    if score >= 9:
        return "CRITICAL"
    if score >= 6:
        return "HIGH"
    if score >= 3:
        return "MEDIUM"
    return "LOW"


def build_alert(rule_id, score, reason, *, entity, name=None, pid=None, ppid=None, path=None,
                username=None, evidence=None, technique=None):
    """Create a normalised alert dict. `entity` groups alerts for correlation."""
    meta = RULE_CATALOG[rule_id]
    score = max(1, min(10, int(score)))
    technique_id = technique or meta["technique"]
    tech_name, tech_tactic = TECHNIQUES.get(technique_id, (meta["technique_name"], meta["tactic"]))
    digest = hashlib.sha1(f"{rule_id}|{entity}|{reason}".encode("utf-8", "ignore")).hexdigest()[:12]
    return {
        "alert_id": digest,
        "timestamp": now_str(),
        "rule_id": rule_id,
        "rule_name": meta["name"],
        "alert_type": meta["alert_type"],
        "severity": severity_from_score(score),
        "score": score,
        "name": name,
        "pid": pid,
        "ppid": ppid,
        "path": path,
        "username": username,
        "reason": reason,
        "mitre_id": technique_id,
        "mitre_technique": tech_name,
        "mitre_tactic": tech_tactic,
        "recommendation": meta["recommendation"],
        "entity": entity,
        "evidence": evidence or {},
    }


def _matches(alert, rule):
    checks = 0
    if "rule_id" in rule:
        checks += 1
        if alert["rule_id"] != rule["rule_id"]:
            return False
    if "name" in rule:
        checks += 1
        if str(alert.get("name") or "").lower() != str(rule["name"]).lower():
            return False
    if "path_contains" in rule:
        checks += 1
        if str(rule["path_contains"]).lower() not in str(alert.get("path") or "").lower():
            return False
    return checks > 0


def apply_suppressions(alerts, suppressions):
    """Drop alerts matching any analyst suppression (all given fields must match)."""
    if not suppressions:
        return alerts, 0
    kept = [a for a in alerts if not any(_matches(a, rule) for rule in suppressions)]
    return kept, len(alerts) - len(kept)


def correlate(alerts):
    """Add CORR-001 when independent rules agree on the same entity."""
    groups = defaultdict(list)
    for alert in alerts:
        groups[alert["entity"]].append(alert)

    extra = []
    for entity, items in groups.items():
        rules = {a["rule_id"] for a in items}
        if len(rules) < 2:
            continue
        scores = sorted((a["score"] for a in items), reverse=True)
        score = min(10, scores[0] + 2 * (len(rules) - 1))
        if SEVERITY_RANK[severity_from_score(score)] <= max(SEVERITY_RANK[a["severity"]] for a in items):
            continue
        first = items[0]
        extra.append(build_alert(
            "CORR-001", score,
            f"{len(rules)} independent detections fired for the same entity: " + ", ".join(sorted(rules)),
            entity=entity, name=first.get("name"), pid=first.get("pid"), ppid=first.get("ppid"),
            path=first.get("path"), username=first.get("username"),
            evidence={"rules": sorted(rules), "individual_scores": scores}))
    return alerts + extra


def finalize(alerts, suppressions=None):
    """Suppress, correlate, de-duplicate and sort (highest score first)."""
    alerts, suppressed = apply_suppressions(alerts, suppressions or [])
    alerts = correlate(alerts)
    seen, unique = set(), []
    for alert in alerts:
        if alert["alert_id"] in seen:
            continue
        seen.add(alert["alert_id"])
        unique.append(alert)
    unique.sort(key=lambda a: (-a["score"], a["rule_id"], str(a.get("name"))))
    return unique, suppressed
