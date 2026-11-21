"""Persistence detections (PERS-xxx): Run keys, Startup folders and scheduled tasks."""

from agent.alerts import build_alert
from agent.enrichment import SIG_VALID
from agent.pathutils import display_dir, in_trusted_root, is_packaged_app, writable_tier
from agent.process_rules import BAD_SIGNATURES
from agent.rules_data import COMMAND_LINE_PATTERNS, SERVICE_INTERPRETER_PATTERN


def startup_key(entry):
    return f'{entry.get("location")}|{entry.get("name")}'


def task_key(task):
    return f'{task.get("task_path")}{task.get("name")}'


def _evaluate(item, new_rule, suspicious_rule, kind, label, key, is_new):
    """Shared logic for startup entries and scheduled tasks."""
    alerts = []
    command = item.get("command") or ""
    exe = item.get("exe") or ""
    status = item.get("sig_status")
    tier = writable_tier(exe, strict=True)
    signed_valid = status == SIG_VALID
    entity = f"{kind}:{key}".lower()

    def make(rule, score, reason, technique=None):
        return build_alert(rule, score, reason, entity=entity, name=item.get("name"), path=command,
                           username=item.get("user"),
                           evidence={"location": label, "command": command, "signature": status,
                                     "signer": item.get("signer"), "sha256": item.get("sha256")},
                           technique=technique)

    reasons = []
    if tier == "temp":
        reasons.append((7, f"launches a binary from a staging directory: {display_dir(exe)}", None))
    elif tier == "profile" and not signed_valid:
        reasons.append((4, f"launches an unsigned binary from a user-profile location: {display_dir(exe)}", None))
    if status in BAD_SIGNATURES:
        reasons.append((8, f"launches a binary with {status} signature", None))
    elif status == "NotSigned" and exe and not in_trusted_root(exe) and tier is None and not is_packaged_app(exe):
        reasons.append((3, "launches an unsigned binary outside Windows/Program Files", None))
    if SERVICE_INTERPRETER_PATTERN.search(command) and tier is not None:
        reasons.append((5, "uses a script engine to run content from a writable location", None))
    for pattern_label, pattern, score, technique in COMMAND_LINE_PATTERNS:
        if pattern.search(command):
            reasons.append((score, f"command matches pattern: {pattern_label}", technique))

    for score, reason, technique in reasons:
        alerts.append(make(suspicious_rule, score, f"{kind.capitalize()} '{item.get('name')}' {reason}.", technique))

    if is_new:
        base = 4 + (2 if reasons else 0)
        alerts.append(make(new_rule, min(base, 8),
                           f"New {kind} '{item.get('name')}' ({label}) was not in the baseline."))
    return alerts


def analyze_startup(entries, baseline=None):
    alerts = []
    for entry in entries:
        is_new = baseline is not None and startup_key(entry) not in baseline
        alerts.extend(_evaluate(entry, "PERS-001", "PERS-002", "startup entry", entry.get("location"),
                                startup_key(entry), is_new))
    return alerts


def analyze_tasks(tasks, baseline=None):
    alerts = []
    for task in tasks:
        is_new = baseline is not None and task_key(task) not in baseline
        alerts.extend(_evaluate(task, "PERS-003", "PERS-004", "scheduled task",
                                task.get("task_path"), task_key(task), is_new))
    return alerts
