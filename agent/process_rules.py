"""Process detections (PROC-xxx): lineage, masquerading, paths, signatures, command lines."""

import os
from collections import defaultdict

from agent.alerts import build_alert
from agent.enrichment import SIG_VALID
from agent.pathutils import (basename, directory, display_dir, in_trusted_root, in_windows_dir, is_packaged_app,
                             is_real_path, levenshtein, norm, writable_tier)
from agent.rules_data import (ALLOWED_PROCESSES, BLACKLISTED_NAME_KEYWORDS, BLACKLISTED_PROCESSES,
                              COMMAND_LINE_PATTERNS, CRITICAL_PROCESSES, DOUBLE_EXTENSION,
                              LOOKALIKE_TARGETS, SINGLETON_PROCESSES, SUSPICIOUS_PARENT_CHILD,
                              SYSTEM_ACCOUNTS)

BROWSER_PARENTS = {"chrome.exe", "msedge.exe", "firefox.exe", "iexplore.exe", "brave.exe"}
BAD_SIGNATURES = {"HashMismatch", "NotTrusted", "Incompatible", "NotSupportedFileFormat"}


class ProcessIndex:
    """PID lookup with PID-reuse protection and lineage helpers."""

    def __init__(self, processes):
        self.by_pid = {p["pid"]: p for p in processes if p.get("pid") is not None}
        self.children = defaultdict(list)
        for proc in processes:
            parent = self.parent_of(proc)
            if parent:
                self.children[parent["pid"]].append(proc)

    def parent_of(self, proc):
        parent = self.by_pid.get(proc.get("ppid"))
        if not parent or parent["pid"] == proc["pid"]:
            return None
        child_start, parent_start = proc.get("create_time"), parent.get("create_time")
        # A "parent" that started after the child is a recycled PID, not the real parent.
        if child_start and parent_start and parent_start > child_start + 1:
            return None
        return parent

    def lineage(self, proc, depth=6):
        chain, current, seen = [proc], proc, {proc["pid"]}
        while len(chain) < depth:
            parent = self.parent_of(current)
            if not parent or parent["pid"] in seen:
                break
            chain.append(parent)
            seen.add(parent["pid"])
            current = parent
        chain.reverse()
        return " > ".join(f'{p.get("name")}({p["pid"]})' for p in chain)


def allowed_names(custom):
    return ALLOWED_PROCESSES | {str(n).lower() for n in custom.get("allowed_processes", [])}


def blacklist(custom):
    merged = dict(BLACKLISTED_PROCESSES)
    for name in custom.get("blacklisted_processes", []):
        merged[str(name).lower()] = ("analyst blacklist", 8)
    return merged


def trust_label(proc, allowed):
    """Human-friendly trust classification shown in the process inventory."""
    status = proc.get("sig_status")
    if is_packaged_app(proc.get("path")):
        return "Packaged app"
    if status in BAD_SIGNATURES:
        return "Invalid signature"
    if status == "NotSigned":
        return "Unsigned"
    if status == SIG_VALID:
        return "Signed"
    if (proc.get("name") or "").lower() in allowed:
        return "Allowlisted"
    return "Unverified"


def _evidence(proc, index):
    return {
        "cmdline": proc.get("cmdline") or "",
        "lineage": index.lineage(proc),
        "signature": proc.get("sig_status"),
        "signer": proc.get("signer"),
        "sha256": proc.get("sha256"),
        "started": proc.get("started"),
    }


def _alert(rule_id, score, reason, proc, index, technique=None, extra=None):
    evidence = _evidence(proc, index)
    if extra:
        evidence.update(extra)
    return build_alert(
        rule_id, score, reason,
        entity=f'proc:{proc["pid"]}:{(proc.get("name") or "").lower()}',
        name=proc.get("name"), pid=proc.get("pid"), ppid=proc.get("ppid"),
        path=proc.get("path"), username=proc.get("username"),
        evidence=evidence, technique=technique)


def analyze_processes(processes, custom=None, ioc_hashes=None):
    custom = custom or {}
    ioc_hashes = ioc_hashes or set()
    allowed = allowed_names(custom)
    deny = blacklist(custom)
    index = ProcessIndex(processes)
    alerts = []

    for proc in processes:
        name = (proc.get("name") or "")
        lname = name.lower()
        if not lname:
            continue
        path = proc.get("path") or ""
        npath = norm(path)
        status = proc.get("sig_status")
        signed_valid = status == SIG_VALID
        tier = writable_tier(path)
        parent = index.parent_of(proc)
        pname = (parent.get("name") or "").lower() if parent else ""

        # PROC-001 suspicious parent -> child
        rule = SUSPICIOUS_PARENT_CHILD.get(pname, {}).get(lname)
        if rule:
            score, technique, note = rule
            if pname in BROWSER_PARENTS and ("-extension://" in (proc.get("cmdline") or "")):
                score, note = 2, "Browser native-messaging host launched through a shell (usually a benign extension helper)"
            alerts.append(_alert("PROC-001", score, f"{note}: {parent['name']} -> {name}",
                                 proc, index, technique=technique,
                                 extra={"parent_pid": parent["pid"], "parent_name": parent["name"]}))

        # PROC-002 user-writable execution directory
        if tier == "temp":
            alerts.append(_alert("PROC-002", 7 if not signed_valid else 4,
                                 f"Executable runs from a staging directory: {display_dir(path)}", proc, index))
        elif tier == "profile" and not signed_valid and status is not None:
            alerts.append(_alert("PROC-002", 4,
                                 f"Unsigned executable runs from a user-profile directory: {display_dir(path)}",
                                 proc, index))

        # PROC-003 unsigned and not allow-listed
        if lname not in allowed and is_real_path(path) and not is_packaged_app(path):
            if status == "NotSigned":
                alerts.append(_alert("PROC-003", 5 if tier else (2 if in_trusted_root(path) else 3),
                                     "Process is not on the allowlist and has no digital signature.", proc, index))
            elif status is None:
                alerts.append(_alert("PROC-003", 2,
                                     "Process is not on the allowlist (signature not verified).", proc, index))

        # PROC-004 blacklist
        hit = deny.get(lname)
        if not hit:
            for keyword, info in BLACKLISTED_NAME_KEYWORDS.items():
                if keyword in lname:
                    hit = info
                    break
        if hit:
            alerts.append(_alert("PROC-004", hit[1], f"Process matches a blacklisted tool: {name} ({hit[0]}).",
                                 proc, index))

        # PROC-005 critical process in the wrong place / PROC-007 wrong parent
        spec = CRITICAL_PROCESSES.get(lname)
        if spec and path and directory(path) not in spec["dirs"]:
            alerts.append(_alert("PROC-005", 9 if not signed_valid else 7,
                                 f"{name} should run from {sorted(spec['dirs'])[0]} but runs from {display_dir(path)}.",
                                 proc, index))
        if spec and parent and pname not in spec["parents"]:
            alerts.append(_alert("PROC-007", 8,
                                 f"{name} has unexpected parent {parent['name']} (expected: "
                                 f"{', '.join(sorted(spec['parents']))}).", proc, index,
                                 extra={"parent_pid": parent["pid"], "parent_name": parent["name"]}))

        # PROC-006 look-alike names
        if lname not in allowed and lname not in CRITICAL_PROCESSES and not signed_valid and len(lname) >= 5:
            normalized = lname.replace("0", "o").replace("1", "l")
            for target in LOOKALIKE_TARGETS:
                limit = 1 if len(target) <= 9 else 2
                if normalized != target and levenshtein(normalized, target) <= limit:
                    alerts.append(_alert("PROC-006", 7, f"{name} imitates the Windows process {target}.",
                                         proc, index))
                    break
                if lname != target and normalized == target:
                    alerts.append(_alert("PROC-006", 7, f"{name} imitates {target} using look-alike characters.",
                                         proc, index))
                    break

        # PROC-008 command line
        cmdline = proc.get("cmdline") or ""
        if cmdline:
            for label, pattern, score, technique in COMMAND_LINE_PATTERNS:
                if pattern.search(cmdline):
                    alerts.append(_alert("PROC-008", score, f"{label} detected in command line.",
                                         proc, index, technique=technique))

        # PROC-010 SYSTEM-level from a non-standard path
        user = (proc.get("username") or "").lower()
        if (user in SYSTEM_ACCOUNTS and path and not in_trusted_root(path) and not signed_valid
                and status is not None):
            alerts.append(_alert("PROC-010", 7,
                                 f"Process runs as {proc.get('username')} from non-standard path {display_dir(path)}.",
                                 proc, index))

        # PROC-011 image deleted from disk
        if path and norm(path)[1:3] == ":\\":
            if "image_missing" in proc:          # explicit flag (synthetic / replayed data)
                missing = bool(proc["image_missing"])
            elif os.name == "nt":
                try:
                    os.stat(path)
                    missing = False
                except FileNotFoundError:
                    missing = True
                except OSError:
                    missing = False
            else:
                missing = False
            if missing:
                alerts.append(_alert("PROC-011", 6, "Process image no longer exists on disk.", proc, index))

        # PROC-012 double extension
        if DOUBLE_EXTENSION.search(lname):
            alerts.append(_alert("PROC-012", 7, f"Executable uses a deceptive double extension: {name}.",
                                 proc, index))

        # PROC-013 signature problems
        if status in BAD_SIGNATURES and not is_packaged_app(path):
            alerts.append(_alert("PROC-013", 8, f"Digital signature is {status}: the file may be tampered with.",
                                 proc, index))
        elif status == "NotSigned" and in_windows_dir(path) and lname in allowed and not is_packaged_app(path):
            alerts.append(_alert("PROC-013", 5, "System-directory binary has no digital signature.", proc, index))

        # PROC-014 IOC hash
        sha = (proc.get("sha256") or "").lower()
        if sha and sha in ioc_hashes:
            alerts.append(_alert("PROC-014", 10, "Executable hash matches a known-bad IOC.", proc, index))

    # PROC-009 duplicate singletons (the newest instance is the suspect)
    groups = defaultdict(list)
    for proc in processes:
        lname = (proc.get("name") or "").lower()
        if lname in SINGLETON_PROCESSES:
            groups[lname].append(proc)
    for lname, items in groups.items():
        if len(items) > 1:
            items.sort(key=lambda p: p.get("create_time") or 0)
            for extra in items[1:]:
                alerts.append(_alert("PROC-009", 8,
                                     f"Multiple {lname} instances running; Windows only runs one.", extra, index))
    return alerts
