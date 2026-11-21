"""Telemetry collection: processes, services, startup entries, scheduled tasks."""

import ctypes
import json
import logging
import os
import subprocess
import tempfile
from datetime import datetime

try:
    import psutil
except ImportError:  # pragma: no cover - psutil is a hard requirement at runtime
    psutil = None

try:
    import winreg
except ImportError:  # non-Windows (tests / dashboard hosting)
    winreg = None

from agent.config import POWERSHELL_TIMEOUT_SECONDS, PS_DIR
from agent.pathutils import parse_exe

log = logging.getLogger("monitor.collect")

CREATE_NO_WINDOW = 0x08000000 if os.name == "nt" else 0


def now_str():
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")


def is_admin():
    try:
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:
        return False


def run_powershell(script, *args, timeout=POWERSHELL_TIMEOUT_SECONDS):
    """Run a bundled .ps1 script and return its CompletedProcess (None on launch failure)."""
    command = [
        "powershell.exe", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass",
        "-File", str(PS_DIR / script), *[str(a) for a in args],
    ]
    try:
        return subprocess.run(command, capture_output=True, text=True, encoding="utf-8",
                              errors="ignore", timeout=timeout, creationflags=CREATE_NO_WINDOW)
    except (OSError, subprocess.SubprocessError) as exc:
        log.error("PowerShell script %s failed: %s", script, exc)
        return None


def _json_rows(text):
    text = (text or "").strip().lstrip("﻿")
    if not text:
        return []
    try:
        data = json.loads(text)
    except ValueError:
        return []
    if isinstance(data, dict):
        return [data]
    return [row for row in data if isinstance(row, dict)]


def run_json_script(script, items):
    """Pass `items` to a PowerShell script as a JSON file and return its JSON rows."""
    with tempfile.TemporaryDirectory(prefix="wspm_") as tmp:
        in_file, out_file = os.path.join(tmp, "in.json"), os.path.join(tmp, "out.json")
        with open(in_file, "w", encoding="utf-8") as handle:
            json.dump(items, handle)
        result = run_powershell(script, in_file, out_file)
        if result is None or result.returncode != 0 or not os.path.exists(out_file):
            log.warning("%s unavailable: %s", script, getattr(result, "stderr", "").strip()[:200])
            return None
        with open(out_file, encoding="utf-8-sig") as handle:
            return _json_rows(handle.read())


# ---------------------------------------------------------------------------
# Processes
# ---------------------------------------------------------------------------

def _own_process_tree():
    """PIDs of this agent and every descendant (excluded so we never alert on ourselves)."""
    pids = {os.getpid()}
    try:
        me = psutil.Process()
        pids.update(child.pid for child in me.children(recursive=True))
        parent = me.parent()      # the `python.exe` launcher stub that spawned the real interpreter
        if parent and (parent.name() or "").lower().startswith("python"):
            pids.add(parent.pid)
    except psutil.Error:
        pass
    return pids


def collect_processes(exclude_self=True):
    if psutil is None:
        raise RuntimeError("psutil is required: pip install -r requirements.txt")
    excluded = _own_process_tree() if exclude_self else set()
    timestamp = now_str()
    processes = []
    # NB: psutil's per-process "status" call is expensive on Windows (it inspects every thread),
    # so a process that exists in the snapshot is simply reported as "running".
    attrs = ["pid", "ppid", "name", "exe", "username", "cmdline", "create_time"]
    for proc in psutil.process_iter(attrs):
        try:
            info = proc.info
            if info["pid"] in excluded:
                continue
            created = info.get("create_time")
            processes.append({
                "timestamp": timestamp,
                "pid": info["pid"],
                "ppid": info["ppid"],
                "name": info.get("name"),
                "path": info.get("exe") or None,
                "username": info.get("username"),
                "status": "running",
                "cmdline": " ".join(info["cmdline"]) if info.get("cmdline") else "",
                "create_time": created,
                "started": datetime.fromtimestamp(created).strftime("%Y-%m-%d %H:%M:%S") if created else "",
            })
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            continue
    return processes


# ---------------------------------------------------------------------------
# Services
# ---------------------------------------------------------------------------

def collect_services():
    result = run_powershell("services.ps1", timeout=120)
    if result is None or result.returncode != 0:
        log.error("Service enumeration failed: %s", getattr(result, "stderr", ""))
        return []
    timestamp = now_str()
    services = []
    for row in _json_rows(result.stdout):
        path = row.get("PathName")
        services.append({
            "timestamp": timestamp,
            "name": row.get("Name"),
            "display_name": row.get("DisplayName"),
            "state": row.get("State"),
            "start_mode": row.get("StartMode"),
            "start_name": row.get("StartName"),
            "path": path,
            "exe": parse_exe(path),
            "pid": row.get("ProcessId") or None,
        })
    return services


def check_service_acls(services):
    """Audit binary / folder / registry-key permissions; returns {service_name: result}."""
    items = [{"name": s["name"], "exe": s.get("exe") or ""} for s in services if s.get("name")]
    if not items:
        return {}
    rows = run_json_script("service_acl_check.ps1", items) or []
    return {row["name"]: row for row in rows if row.get("name")}


# ---------------------------------------------------------------------------
# Startup entries and scheduled tasks
# ---------------------------------------------------------------------------

_RUN_KEYS = []
if winreg is not None:
    _RUN_KEYS = [
        (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run", "HKLM\\Run"),
        (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce", "HKLM\\RunOnce"),
        (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run", "HKLM\\Run (x86)"),
        (winreg.HKEY_CURRENT_USER, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run", "HKCU\\Run"),
        (winreg.HKEY_CURRENT_USER, r"SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce", "HKCU\\RunOnce"),
    ]


def collect_startup_entries():
    entries = []
    timestamp = now_str()
    for hive, subkey, label in _RUN_KEYS:
        try:
            with winreg.OpenKey(hive, subkey) as key:
                index = 0
                while True:
                    try:
                        name, value, _ = winreg.EnumValue(key, index)
                    except OSError:
                        break
                    index += 1
                    entries.append({"timestamp": timestamp, "location": label, "name": name,
                                    "command": str(value), "exe": parse_exe(str(value))})
        except OSError:
            continue

    folders = [
        ("Startup folder (user)", os.path.join(os.environ.get("APPDATA", ""), r"Microsoft\Windows\Start Menu\Programs\Startup")),
        ("Startup folder (all users)", os.path.join(os.environ.get("PROGRAMDATA", ""), r"Microsoft\Windows\Start Menu\Programs\Startup")),
    ]
    for label, folder in folders:
        if not folder or not os.path.isdir(folder):
            continue
        for item in os.listdir(folder):
            if item.lower() == "desktop.ini":
                continue
            full = os.path.join(folder, item)
            entries.append({"timestamp": timestamp, "location": label, "name": item,
                            "command": full, "exe": full})
    _resolve_shortcuts(entries)
    return entries


def _resolve_shortcuts(entries):
    """Replace .lnk startup items by the command they really launch."""
    links = [e for e in entries if e["exe"].lower().endswith(".lnk")]
    if not links:
        return
    rows = run_json_script("resolve_shortcuts.ps1", [e["exe"] for e in links]) or []
    targets = {r["path"].lower(): r for r in rows if r.get("path")}
    for entry in links:
        row = targets.get(entry["exe"].lower())
        if row and row.get("target"):
            entry["command"] = f'{row["target"]} {row.get("arguments") or ""}'.strip()
            entry["exe"] = row["target"]


def collect_scheduled_tasks():
    result = run_powershell("scheduled_tasks.ps1", timeout=180)
    if result is None or result.returncode != 0:
        return []
    timestamp = now_str()
    tasks = []
    for row in _json_rows(result.stdout):
        if not row.get("execute"):
            continue
        command = f'{row["execute"]} {row.get("arguments") or ""}'.strip()
        tasks.append({"timestamp": timestamp, "name": row.get("name"), "task_path": row.get("path"),
                      "state": row.get("state"), "command": command, "exe": parse_exe(command),
                      "user": row.get("user")})
    return tasks
