"""Service detections (SVC-xxx) including baseline drift, permissions and signatures."""

from agent.alerts import build_alert
from agent.enrichment import SIG_VALID
from agent.pathutils import basename, display_dir, in_trusted_root, is_packaged_app, in_windows_dir, is_unquoted_with_spaces, norm, writable_tier
from agent.process_rules import BAD_SIGNATURES
from agent.rules_data import (BLACKLISTED_PROCESSES, COMMAND_LINE_PATTERNS, LOCALSYSTEM_NAMES,
                              SERVICE_INTERPRETER_PATTERN)

TRACKED_FIELDS = ("path", "start_mode", "start_name")


def _alert(rule_id, score, reason, svc, evidence=None, technique=None):
    ev = {
        "display_name": svc.get("display_name"),
        "state": svc.get("state"),
        "start_mode": svc.get("start_mode"),
        "start_name": svc.get("start_name"),
        "image_path": svc.get("path"),
        "signature": svc.get("sig_status"),
        "signer": svc.get("signer"),
        "sha256": svc.get("sha256"),
    }
    ev.update(evidence or {})
    return build_alert(rule_id, score, reason, entity=f'svc:{(svc.get("name") or "").lower()}',
                       name=svc.get("name"), pid=svc.get("pid"), path=svc.get("path"),
                       username=svc.get("start_name"), evidence=ev, technique=technique)


def _is_autostart(svc):
    return (svc.get("start_mode") or "").lower() == "auto"


def _is_system(svc):
    return (svc.get("start_name") or "").lower() in LOCALSYSTEM_NAMES


def analyze_services(services, baseline=None, acl_results=None, custom=None):
    """Return alerts for the given service inventory.

    baseline    -- dict {name: {path,start_mode,start_name,...}} or None (first run).
    acl_results -- {service_name: {file_writable_by, dir_writable_by, key_writable_by}}.
    """
    custom = custom or {}
    acl_results = acl_results or {}
    trusted_names = {str(n).lower() for n in custom.get("trusted_service_names", [])}
    alerts = []

    for svc in services:
        name = svc.get("name") or ""
        if name.lower() in trusted_names:
            continue
        path = svc.get("path") or ""
        exe = svc.get("exe") or ""
        status = svc.get("sig_status")
        signed_valid = status == SIG_VALID
        tier = writable_tier(exe or path, strict=True)

        # SVC-001
        if tier == "temp" or (tier == "profile" and not signed_valid):
            alerts.append(_alert("SVC-001", 8 if tier == "temp" else 6,
                                 f"Service executable is in a user-writable directory: {display_dir(exe or path)}", svc))

        # SVC-002
        if is_unquoted_with_spaces(path):
            alerts.append(_alert("SVC-002", 4 if _is_system(svc) else 3,
                                 "Service ImagePath contains spaces but is not quoted.", svc))

        # SVC-006
        if (_is_autostart(svc) and _is_system(svc) and exe and not in_trusted_root(exe)
                and not signed_valid and status is not None and tier is None):
            alerts.append(_alert("SVC-006", 4,
                                 "Auto-start LocalSystem service runs an unsigned binary outside Windows/Program Files.", svc))

        # SVC-007
        if SERVICE_INTERPRETER_PATTERN.search(path):
            alerts.append(_alert("SVC-007", 7, "Service ImagePath launches a shell or script engine.", svc))
        else:
            for label, pattern, score, technique in COMMAND_LINE_PATTERNS:
                if pattern.search(path):
                    alerts.append(_alert("SVC-007", score, f"{label} in service ImagePath.", svc, technique=technique))

        # SVC-009
        if status in BAD_SIGNATURES:
            alerts.append(_alert("SVC-009", 8, f"Service binary signature is {status}.", svc))
        elif status == "NotSigned" and exe and not in_windows_dir(exe):
            alerts.append(_alert("SVC-009", 4 if tier else 3, "Service binary has no digital signature.", svc))

        # SVC-011
        hit = BLACKLISTED_PROCESSES.get(basename(exe))
        if hit:
            alerts.append(_alert("SVC-011", max(hit[1], 7), f"Service binary is a known tool: {basename(exe)} ({hit[0]}).", svc))

        # SVC-008 / SVC-010
        acl = acl_results.get(name)
        if acl:
            risk = 7 if _is_system(svc) else 6
            if acl.get("file_writable_by"):
                alerts.append(_alert("SVC-008", risk + 1,
                                     "Service binary is writable by " + ", ".join(acl["file_writable_by"]) + ".",
                                     svc, evidence={"writable_by": acl["file_writable_by"], "target": "binary"}))
            elif acl.get("dir_writable_by"):
                alerts.append(_alert("SVC-008", risk,
                                     "Service folder is writable by " + ", ".join(acl["dir_writable_by"]) + ".",
                                     svc, evidence={"writable_by": acl["dir_writable_by"], "target": "folder"}))
            if acl.get("key_writable_by"):
                alerts.append(_alert("SVC-010", risk + 1,
                                     "Service registry key is writable by " + ", ".join(acl["key_writable_by"]) + ".",
                                     svc, evidence={"writable_by": acl["key_writable_by"]}))

    if baseline is not None:
        alerts.extend(_baseline_alerts(services, baseline, trusted_names))
    return alerts


def _baseline_alerts(services, baseline, trusted_names):
    alerts = []
    current = {s["name"]: s for s in services if s.get("name")}

    for name, svc in current.items():
        if name.lower() in trusted_names:
            continue
        previous = baseline.get(name)
        exe = svc.get("exe") or ""
        signed_valid = svc.get("sig_status") == SIG_VALID
        risky = writable_tier(exe, strict=True) == "temp" or (
            svc.get("sig_status") not in (None, SIG_VALID))

        if previous is None:
            score = 5 + (1 if _is_autostart(svc) else 0) + (1 if _is_system(svc) else 0) + (2 if risky else 0)
            if signed_valid and in_trusted_root(exe) and not risky:
                score -= 2
            alerts.append(_alert("SVC-003", min(score, 9),
                                 f"New service '{name}' was not present in the baseline.", svc))
            continue

        changes = {f: (previous.get(f), svc.get(f)) for f in TRACKED_FIELDS if previous.get(f) != svc.get(f)}
        if not changes:
            continue
        score = 4
        # Windows itself flips the start type of some signed system services (e.g. BITS); a start-mode-only
        # change on a validly signed Windows binary is informational, not persistence.
        if (set(changes) == {"start_mode"} and signed_valid and in_windows_dir(exe)
                and (previous.get("start_mode") or "").lower() != "disabled"):
            score = 2
        if "path" in changes:
            score = 7 + (2 if risky else 0)
        if "start_name" in changes and _is_system(svc):
            score = max(score, 7)
        if "start_mode" in changes and (previous.get("start_mode") or "").lower() == "disabled" and _is_autostart(svc):
            score = max(score, 5)
        detail = "; ".join(f"{f}: '{old}' -> '{new}'" for f, (old, new) in changes.items())
        alerts.append(_alert("SVC-004", min(score, 9), f"Service '{name}' changed since baseline ({detail}).",
                             svc, evidence={"changes": {f: {"before": o, "after": n} for f, (o, n) in changes.items()}}))

    for name, old in baseline.items():
        if name not in current and name.lower() not in trusted_names:
            gone = {"name": name, "display_name": old.get("display_name"), "path": old.get("path"),
                    "start_mode": old.get("start_mode"), "start_name": old.get("start_name"), "state": "Removed"}
            alerts.append(_alert("SVC-005", 1, f"Baseline service '{name}' no longer exists.", gone))
    return alerts
