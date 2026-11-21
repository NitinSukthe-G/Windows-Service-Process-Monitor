"""Detection knowledge base: rule catalog, allow/deny lists and pattern libraries.

This module is the single source of truth for the rule documentation
(docs/detection_rules.md is generated from RULE_CATALOG).
"""

import re

# ---------------------------------------------------------------------------
# Rule catalog   (rule_id -> metadata)
# ---------------------------------------------------------------------------

def _rule(name, alert_type, tactic, technique, technique_name, description, recommendation):
    return {
        "name": name,
        "alert_type": alert_type,
        "tactic": tactic,
        "technique": technique,
        "technique_name": technique_name,
        "description": description,
        "recommendation": recommendation,
    }


RULE_CATALOG = {
    "PROC-001": _rule(
        "Suspicious parent-child process chain", "PROCESS_RELATIONSHIP",
        "Execution", "T1204.002", "User Execution: Malicious File",
        "A process that should not normally spawn shells or script hosts (Office, PDF readers, "
        "browsers, web servers, WMI, script hosts, accessibility tools) did so.",
        "Review the full process lineage and command line, isolate the host if the chain is unexpected, "
        "and inspect the document or service that triggered it."),
    "PROC-002": _rule(
        "Process running from user-writable directory", "UNAUTHORIZED_PROCESS",
        "Defense Evasion", "T1036", "Masquerading",
        "The executable runs from Temp, Downloads, Public, Recycle Bin or a similar location commonly "
        "used to stage malware. AppData locations only alert when the binary is not validly signed.",
        "Verify the file origin, hash it, and submit it to a reputation service. Remove it if unknown."),
    "PROC-003": _rule(
        "Unsigned process not on the allowlist", "UNAUTHORIZED_PROCESS",
        "Defense Evasion", "T1036", "Masquerading",
        "The process is not on the allowlist and its executable has no valid Authenticode signature.",
        "Confirm the software is approved; add it to config/custom_rules.json if legitimate."),
    "PROC-004": _rule(
        "Blacklisted tool or malware name", "UNAUTHORIZED_PROCESS",
        "Credential Access", "T1003", "OS Credential Dumping",
        "The process name matches a known offensive tool, credential dumper, tunnelling tool or "
        "crypto-miner on the blacklist.",
        "Treat as an incident: isolate the host, capture memory, and reset exposed credentials."),
    "PROC-005": _rule(
        "System process running from wrong location", "MASQUERADING",
        "Defense Evasion", "T1036.005", "Masquerading: Match Legitimate Name or Location",
        "A core Windows binary name (svchost.exe, lsass.exe, ...) is running outside its expected "
        "directory - a classic malware camouflage technique.",
        "Treat as malicious until proven otherwise; collect the binary and compare its hash with a clean one."),
    "PROC-006": _rule(
        "Look-alike process name", "MASQUERADING",
        "Defense Evasion", "T1036.004", "Masquerading: Masquerade Task or Service",
        "The process name is one or two characters away from a critical Windows process "
        "(e.g. scvhost.exe, svch0st.exe) and is not validly signed.",
        "Inspect the binary, its parent and network activity; remove if not a legitimate product."),
    "PROC-007": _rule(
        "Unexpected parent for critical system process", "PROCESS_RELATIONSHIP",
        "Defense Evasion", "T1055", "Process Injection",
        "A critical Windows process has a parent other than the one Windows always uses "
        "(e.g. svchost.exe not started by services.exe). This is a sign of spoofing or injection.",
        "Dump the process and its parent for analysis and verify with an EDR/Sysmon process-creation log."),
    "PROC-008": _rule(
        "Suspicious command line", "COMMAND_LINE",
        "Execution", "T1059", "Command and Scripting Interpreter",
        "The command line contains a known attack pattern: encoded PowerShell, download cradles, "
        "LOLBin abuse, shadow-copy deletion, firewall/Defender tampering and similar.",
        "Decode and review the command, identify the launching parent, and hunt for the same pattern fleet-wide."),
    "PROC-009": _rule(
        "Duplicate singleton system process", "MASQUERADING",
        "Defense Evasion", "T1036.005", "Masquerading: Match Legitimate Name or Location",
        "More than one instance of a process that Windows only ever runs once (lsass.exe, "
        "services.exe, wininit.exe) exists.",
        "The newest instance is almost certainly malicious; capture and terminate it."),
    "PROC-010": _rule(
        "SYSTEM-level process from non-standard path", "UNAUTHORIZED_PROCESS",
        "Privilege Escalation", "T1543", "Create or Modify System Process",
        "A process runs as SYSTEM / service account from outside Windows or Program Files and "
        "without a valid signature.",
        "Identify the installing service or task; privilege-escalation or persistence is likely."),
    "PROC-011": _rule(
        "Executable missing on disk", "UNAUTHORIZED_PROCESS",
        "Defense Evasion", "T1070.004", "Indicator Removal: File Deletion",
        "The process image path no longer exists on disk - the binary was deleted after launch "
        "(or the process was hollowed).",
        "Dump process memory before termination; the on-disk artefact is gone."),
    "PROC-012": _rule(
        "Double-extension executable", "UNAUTHORIZED_PROCESS",
        "Defense Evasion", "T1036.007", "Masquerading: Double File Extension",
        "The executable is named like a document (invoice.pdf.exe) to trick the user.",
        "Quarantine the file and review the delivery channel (email / download)."),
    "PROC-013": _rule(
        "Invalid or missing signature on system binary", "UNAUTHORIZED_PROCESS",
        "Defense Evasion", "T1553.002", "Subvert Trust Controls: Code Signing",
        "The signature is invalid / hash-mismatched / untrusted, or a binary in the Windows "
        "directory is unsigned - possible tampering or trojanised binary.",
        "Compare the file against a known-good copy (sfc /scannow) and investigate how it was modified."),
    "PROC-014": _rule(
        "Known-bad file hash (IOC match)", "UNAUTHORIZED_PROCESS",
        "Execution", "T1204", "User Execution",
        "The SHA-256 hash of the running executable matches an entry in config/ioc_hashes.txt.",
        "Confirmed malicious by threat intelligence - begin incident response."),
    "SVC-001": _rule(
        "Service binary in user-writable directory", "SERVICE",
        "Persistence", "T1543.003", "Create or Modify System Process: Windows Service",
        "A Windows service executable lives in Temp, AppData, Public, Users or another directory "
        "writable by standard users.",
        "Disable the service, collect the binary, and review how it was registered (event 7045)."),
    "SVC-002": _rule(
        "Unquoted service path", "SERVICE",
        "Privilege Escalation", "T1574.009", "Hijack Execution Flow: Path Interception by Unquoted Path",
        "The service image path contains spaces and is not quoted, allowing Windows to execute an "
        "attacker-placed binary earlier in the path.",
        "Quote the ImagePath value in HKLM\\SYSTEM\\CurrentControlSet\\Services\\<name>."),
    "SVC-003": _rule(
        "New service since baseline", "SERVICE",
        "Persistence", "T1543.003", "Create or Modify System Process: Windows Service",
        "A service exists that was not present when the baseline was captured.",
        "Confirm an approved install; otherwise disable it and investigate. Re-baseline with --update-baseline once reviewed."),
    "SVC-004": _rule(
        "Modified service since baseline", "SERVICE",
        "Persistence", "T1543.003", "Create or Modify System Process: Windows Service",
        "The binary path, start type or logon account of an existing service changed since the baseline.",
        "Check change records; a changed binary path or SYSTEM logon account is a strong persistence indicator."),
    "SVC-005": _rule(
        "Service removed since baseline", "SERVICE",
        "Defense Evasion", "T1070", "Indicator Removal",
        "A baseline service no longer exists (informational; may be an uninstall or anti-forensic clean-up).",
        "Confirm an approved uninstall."),
    "SVC-006": _rule(
        "Non-standard autostart SYSTEM service", "SERVICE",
        "Persistence", "T1543.003", "Create or Modify System Process: Windows Service",
        "An auto-start service running as LocalSystem has a binary outside Windows / Program Files "
        "and is not validly signed.",
        "Validate the vendor and installer; move to a least-privilege account if possible."),
    "SVC-007": _rule(
        "Suspicious service command line", "SERVICE",
        "Execution", "T1569.002", "System Services: Service Execution",
        "The service image path launches a shell or script engine, or contains an attack pattern "
        "(PsExec / Metasploit-style service creation).",
        "Disable the service and review event 7045 / 4697 for the creating account."),
    "SVC-008": _rule(
        "Weak permissions on service binary or folder", "SERVICE",
        "Privilege Escalation", "T1574.010", "Hijack Execution Flow: Services File Permissions Weakness",
        "Standard users (Everyone / Authenticated Users / Users) can modify the service executable "
        "or its directory, allowing replacement with a malicious binary that runs as the service account.",
        "Remove write access for non-administrators on the binary and directory."),
    "SVC-009": _rule(
        "Unsigned or invalid-signature service binary", "SERVICE",
        "Defense Evasion", "T1553.002", "Subvert Trust Controls: Code Signing",
        "The service executable outside the Windows directory has no valid signature, or its "
        "signature is invalid / tampered.",
        "Verify the vendor; submit the hash to a reputation service."),
    "SVC-010": _rule(
        "Weak permissions on service registry key", "SERVICE",
        "Privilege Escalation", "T1574.011", "Hijack Execution Flow: Services Registry Permissions Weakness",
        "Standard users can modify HKLM\\SYSTEM\\CurrentControlSet\\Services\\<name>, allowing "
        "them to change ImagePath and run code as the service account.",
        "Reset the key ACL so only SYSTEM and Administrators have write access."),
    "SVC-011": _rule(
        "Blacklisted service binary", "SERVICE",
        "Lateral Movement", "T1021.002", "Remote Services: SMB/Windows Admin Shares",
        "The service executable matches a known offensive or remote-execution tool (e.g. PSEXESVC).",
        "Identify the remote source and the account used; treat as lateral movement."),
    "PERS-001": _rule(
        "New startup entry since baseline", "PERSISTENCE",
        "Persistence", "T1547.001", "Boot or Logon Autostart Execution: Registry Run Keys / Startup Folder",
        "A Run/RunOnce registry value or Startup-folder item exists that was not in the baseline.",
        "Verify the entry with its owner; remove it if unrecognised."),
    "PERS-002": _rule(
        "Startup entry in suspicious location or command", "PERSISTENCE",
        "Persistence", "T1547.001", "Boot or Logon Autostart Execution: Registry Run Keys / Startup Folder",
        "A startup entry launches code from a user-writable directory, an unsigned binary, or a "
        "command line matching an attack pattern.",
        "Remove the entry and collect the referenced file."),
    "PERS-003": _rule(
        "New scheduled task since baseline", "PERSISTENCE",
        "Persistence", "T1053.005", "Scheduled Task/Job: Scheduled Task",
        "A scheduled task exists that was not present in the baseline.",
        "Review the task action, author and trigger."),
    "PERS-004": _rule(
        "Scheduled task with suspicious action", "PERSISTENCE",
        "Persistence", "T1053.005", "Scheduled Task/Job: Scheduled Task",
        "A scheduled task runs a binary from a user-writable directory, an unsigned binary, or a "
        "command matching an attack pattern.",
        "Disable the task and collect the referenced file."),
    "CORR-001": _rule(
        "Multiple indicators on one entity", "CORRELATION",
        "Multiple", "-", "Behavioural correlation",
        "Two or more independent rules fired for the same process, service or startup item, which "
        "raises confidence far above any single indicator.",
        "Prioritise this entity - independent signals agreeing is the strongest evidence this tool produces."),
}

# ---------------------------------------------------------------------------
# Severity
# ---------------------------------------------------------------------------

SEVERITY_ORDER = ["CRITICAL", "HIGH", "MEDIUM", "LOW"]
SEVERITY_RANK = {name: len(SEVERITY_ORDER) - i for i, name in enumerate(SEVERITY_ORDER)}

# ---------------------------------------------------------------------------
# Allow-list (lower-case names). Unlisted + validly signed processes do not alert;
# unlisted + unsigned processes do. Extend via config/custom_rules.json.
# ---------------------------------------------------------------------------

ALLOWED_PROCESSES = {
    # Kernel / core
    "system", "system idle process", "registry", "memory compression", "secure system",
    "smss.exe", "csrss.exe", "wininit.exe", "winlogon.exe", "services.exe", "lsass.exe",
    "lsaiso.exe", "lsm.exe", "svchost.exe", "fontdrvhost.exe", "dwm.exe", "logonui.exe",
    "sihost.exe", "taskhost.exe", "taskhostw.exe", "dllhost.exe", "conhost.exe", "audiodg.exe",
    "spoolsv.exe", "wmiprvse.exe", "wudfhost.exe", "dashost.exe", "unsecapp.exe", "ngciso.exe",
    "msiexec.exe", "werfault.exe", "wermgr.exe", "userinit.exe", "smartscreen.exe",
    "backgroundtaskhost.exe", "ctfmon.exe", "lockapp.exe", "useroobebroker.exe",
    # Shell / UI
    "explorer.exe", "runtimebroker.exe", "searchhost.exe", "searchapp.exe", "searchindexer.exe",
    "searchprotocolhost.exe", "searchfilterhost.exe", "startmenuexperiencehost.exe",
    "shellexperiencehost.exe", "textinputhost.exe", "applicationframehost.exe", "systemsettings.exe",
    "widgets.exe", "widgetservice.exe", "phoneexperiencehost.exe", "crossdeviceservice.exe",
    "taskmgr.exe", "notepad.exe", "mmc.exe", "regedit.exe", "mspaint.exe", "snippingtool.exe",
    # Security
    "securityhealthservice.exe", "securityhealthsystray.exe", "msmpeng.exe", "nissrv.exe",
    "mpdefendercoreservice.exe", "sgrmbroker.exe",
    # Shells and developer tooling
    "cmd.exe", "powershell.exe", "pwsh.exe", "windowsterminal.exe", "wt.exe", "openconsole.exe",
    "python.exe", "pythonw.exe", "py.exe", "git.exe", "node.exe", "code.exe", "claude.exe",
    # Common user applications
    "msedge.exe", "msedgewebview2.exe", "chrome.exe", "firefox.exe", "brave.exe", "iexplore.exe",
    "onedrive.exe", "teams.exe", "ms-teams.exe", "outlook.exe", "winword.exe", "excel.exe",
    "powerpnt.exe", "onenote.exe", "acrobat.exe", "acrord32.exe",
}

# Offensive / unwanted tools:  name -> (category, score, short MITRE note)
BLACKLISTED_PROCESSES = {
    "mimikatz.exe": ("credential dumper", 10),
    "mimilib.dll": ("credential dumper", 10),
    "procdump.exe": ("process dump utility (LSASS dumping)", 6),
    "procdump64.exe": ("process dump utility (LSASS dumping)", 6),
    "pwdump.exe": ("credential dumper", 10),
    "gsecdump.exe": ("credential dumper", 10),
    "wce.exe": ("credential dumper", 10),
    "fgdump.exe": ("credential dumper", 10),
    "lazagne.exe": ("credential harvester", 10),
    "rubeus.exe": ("Kerberos abuse tool", 10),
    "sharphound.exe": ("Active Directory recon", 8),
    "bloodhound.exe": ("Active Directory recon", 8),
    "adfind.exe": ("Active Directory recon", 6),
    "psexec.exe": ("remote execution tool", 6),
    "psexec64.exe": ("remote execution tool", 6),
    "psexesvc.exe": ("remote execution service", 7),
    "paexec.exe": ("remote execution tool", 6),
    "nc.exe": ("netcat network backdoor", 8),
    "nc64.exe": ("netcat network backdoor", 8),
    "ncat.exe": ("netcat network backdoor", 7),
    "netcat.exe": ("netcat network backdoor", 8),
    "plink.exe": ("SSH tunnelling tool", 5),
    "chisel.exe": ("tunnelling tool", 8),
    "ngrok.exe": ("tunnelling tool", 5),
    "frpc.exe": ("reverse proxy / tunnelling tool", 7),
    "nmap.exe": ("network scanner", 5),
    "masscan.exe": ("network scanner", 6),
    "fscan.exe": ("network scanner", 7),
    "hydra.exe": ("password brute-forcer", 8),
    "john.exe": ("password cracker", 6),
    "hashcat.exe": ("password cracker", 6),
    "crackmapexec.exe": ("lateral movement framework", 9),
    "winpeas.exe": ("privilege-escalation enumeration", 7),
    "winpeasx64.exe": ("privilege-escalation enumeration", 7),
    "seatbelt.exe": ("host reconnaissance", 7),
    "beacon.exe": ("C2 implant", 10),
    "meterpreter.exe": ("C2 implant", 10),
    "xmrig.exe": ("crypto-miner", 8),
    "minerd.exe": ("crypto-miner", 8),
    "cpuminer.exe": ("crypto-miner", 8),
    "nbminer.exe": ("crypto-miner", 8),
    "t-rex.exe": ("crypto-miner", 8),
}
BLACKLISTED_NAME_KEYWORDS = {
    "mimikatz": ("credential dumper", 10),
    "meterpreter": ("C2 implant", 10),
    "cobaltstrike": ("C2 implant", 10),
    "xmrig": ("crypto-miner", 8),
}

# ---------------------------------------------------------------------------
# Critical Windows processes: expected directory + legitimate parent(s)
# ---------------------------------------------------------------------------

SYSTEM32_DIRS = {"c:\\windows\\system32", "c:\\windows\\syswow64"}

CRITICAL_PROCESSES = {
    "smss.exe":     {"dirs": SYSTEM32_DIRS, "parents": {"smss.exe", "system"}},
    "csrss.exe":    {"dirs": SYSTEM32_DIRS, "parents": {"smss.exe"}},
    "wininit.exe":  {"dirs": SYSTEM32_DIRS, "parents": {"smss.exe"}},
    "winlogon.exe": {"dirs": SYSTEM32_DIRS, "parents": {"smss.exe"}},
    "services.exe": {"dirs": SYSTEM32_DIRS, "parents": {"wininit.exe"}},
    "lsass.exe":    {"dirs": SYSTEM32_DIRS, "parents": {"wininit.exe"}},
    "lsm.exe":      {"dirs": SYSTEM32_DIRS, "parents": {"wininit.exe"}},
    "svchost.exe":  {"dirs": SYSTEM32_DIRS, "parents": {"services.exe", "msmpeng.exe"}},
    "taskhostw.exe": {"dirs": SYSTEM32_DIRS, "parents": {"svchost.exe", "services.exe"}},
    "spoolsv.exe":  {"dirs": SYSTEM32_DIRS, "parents": {"services.exe"}},
    "explorer.exe": {"dirs": {"c:\\windows"}, "parents": {"userinit.exe", "winlogon.exe", "explorer.exe"}},
}
SINGLETON_PROCESSES = {"lsass.exe", "services.exe", "wininit.exe"}
LOOKALIKE_TARGETS = [
    "svchost.exe", "lsass.exe", "csrss.exe", "services.exe", "winlogon.exe", "explorer.exe",
    "smss.exe", "wininit.exe", "spoolsv.exe", "taskhost.exe", "taskhostw.exe", "dllhost.exe",
    "conhost.exe", "rundll32.exe", "powershell.exe", "runtimebroker.exe",
]

# ---------------------------------------------------------------------------
# Suspicious parent -> child relationships
# parent -> {child: (score, MITRE id, note)}
# ---------------------------------------------------------------------------

_SHELLS = ("powershell.exe", "pwsh.exe", "cmd.exe", "wscript.exe", "cscript.exe", "mshta.exe")
_LOLBINS = ("rundll32.exe", "regsvr32.exe", "certutil.exe", "bitsadmin.exe", "msbuild.exe", "wmic.exe",
            "schtasks.exe", "installutil.exe", "regasm.exe", "regsvcs.exe", "cmstp.exe", "msiexec.exe")


def _children(names, score, technique, note):
    return {name: (score, technique, note) for name in names}


_OFFICE_CHILDREN = {}
_OFFICE_CHILDREN.update(_children(_SHELLS + _LOLBINS, 8, "T1204.002", "Office/PDF application spawned a shell or LOLBin (malicious macro / exploit)"))

SUSPICIOUS_PARENT_CHILD = {}
for _parent in ("winword.exe", "excel.exe", "powerpnt.exe", "outlook.exe", "msaccess.exe", "mspub.exe",
                "visio.exe", "onenote.exe", "acrord32.exe", "acrobat.exe", "foxitreader.exe", "eqnedt32.exe"):
    SUSPICIOUS_PARENT_CHILD[_parent] = dict(_OFFICE_CHILDREN)

for _parent in ("chrome.exe", "msedge.exe", "firefox.exe", "iexplore.exe", "brave.exe"):
    SUSPICIOUS_PARENT_CHILD[_parent] = _children(
        _SHELLS + ("certutil.exe", "bitsadmin.exe", "regsvr32.exe"), 6, "T1189",
        "Browser spawned a shell or LOLBin (drive-by download / exploit)")

for _parent in ("wscript.exe", "cscript.exe", "mshta.exe"):
    SUSPICIOUS_PARENT_CHILD[_parent] = _children(
        ("powershell.exe", "pwsh.exe", "cmd.exe", "rundll32.exe", "regsvr32.exe", "certutil.exe", "bitsadmin.exe"),
        7, "T1059.005", "Script host launched a second-stage payload")

SUSPICIOUS_PARENT_CHILD["wmiprvse.exe"] = _children(
    ("powershell.exe", "pwsh.exe", "cmd.exe", "mshta.exe"), 7, "T1047", "WMI provider host spawned a shell (remote WMI execution)")
SUSPICIOUS_PARENT_CHILD["spoolsv.exe"] = _children(
    ("powershell.exe", "pwsh.exe", "cmd.exe"), 7, "T1068", "Print Spooler spawned a shell (PrintNightmare-style exploit)")
SUSPICIOUS_PARENT_CHILD["lsass.exe"] = _children(
    _SHELLS + _LOLBINS, 9, "T1003", "LSASS spawned a child process (credential theft / injection)")
for _parent in ("w3wp.exe", "httpd.exe", "nginx.exe", "tomcat9.exe", "sqlservr.exe"):
    SUSPICIOUS_PARENT_CHILD[_parent] = _children(
        ("powershell.exe", "pwsh.exe", "cmd.exe", "certutil.exe", "bitsadmin.exe"), 8, "T1505.003",
        "Web/database server spawned a shell (web shell / command injection)")
for _parent in ("sethc.exe", "utilman.exe", "osk.exe", "magnify.exe", "narrator.exe", "displayswitch.exe", "atbroker.exe"):
    SUSPICIOUS_PARENT_CHILD[_parent] = _children(
        ("cmd.exe", "powershell.exe", "pwsh.exe"), 9, "T1546.008",
        "Accessibility tool spawned a shell (sticky-keys style backdoor)")

# ---------------------------------------------------------------------------
# Command-line patterns:  (label, regex, score, MITRE id)
# ---------------------------------------------------------------------------

_I = re.IGNORECASE
COMMAND_LINE_PATTERNS = [
    ("Encoded PowerShell command", re.compile(r"(powershell|pwsh)\S*\s.*-(e|ec|en|enc|enco|encod|encode|encoded|encodedcommand)\s+[A-Za-z0-9+/=]{20,}", _I), 6, "T1027"),
    ("PowerShell download cradle", re.compile(r"(downloadstring|downloadfile|downloaddata|net\.webclient|invoke-webrequest|\biwr\b|start-bitstransfer|invoke-restmethod)", _I), 4, "T1105"),
    ("PowerShell hidden window + policy bypass", re.compile(r"(powershell|pwsh)\S*\s.*(-w(indowstyle)?\s+hidden).*(-exec(utionpolicy)?\s+bypass)|(powershell|pwsh)\S*\s.*(-exec(utionpolicy)?\s+bypass).*(-w(indowstyle)?\s+hidden)", _I), 6, "T1059.001"),
    ("PowerShell Invoke-Expression of remote content", re.compile(r"(iex|invoke-expression)\s*\(?.*(http|downloadstring|frombase64string)", _I), 6, "T1059.001"),
    ("Certutil used to download or decode", re.compile(r"certutil(\.exe)?\s.*-(urlcache|decode|verifyctl)", _I), 6, "T1105"),
    ("BITSAdmin transfer", re.compile(r"bitsadmin(\.exe)?\s.*/transfer", _I), 5, "T1197"),
    ("Regsvr32 remote scriptlet (Squiblydoo)", re.compile(r"regsvr32(\.exe)?\s.*(/i:\s*https?://|scrobj\.dll)", _I), 8, "T1218.010"),
    ("Mshta executing remote or inline script", re.compile(r"mshta(\.exe)?\s.*(https?://|vbscript:|javascript:)", _I), 8, "T1218.005"),
    ("Rundll32 executing script or URL", re.compile(r"rundll32(\.exe)?\s.*(javascript:|vbscript:|https?://)", _I), 7, "T1218.011"),
    ("WMIC remote / process creation", re.compile(r"wmic(\.exe)?\s.*(process\s+call\s+create|/node:)", _I), 6, "T1047"),
    ("Shadow copy / backup deletion (ransomware behaviour)", re.compile(r"(vssadmin(\.exe)?\s.*delete\s+shadows|wmic(\.exe)?\s.*shadowcopy\s+delete|wbadmin(\.exe)?\s.*delete\s+(catalog|backup)|bcdedit(\.exe)?\s.*(recoveryenabled\s+no|bootstatuspolicy\s+ignoreallfailures))", _I), 10, "T1490"),
    ("LSASS memory dump", re.compile(r"(comsvcs\.dll.*minidump|procdump(64)?(\.exe)?\s.*lsass|sekurlsa|lsass.*\.dmp)", _I), 10, "T1003.001"),
    ("Windows Defender tampering", re.compile(r"(set-mppreference\s.*-disable\w+\s+\$?true|add-mppreference\s.*-exclusion|sc(\.exe)?\s+(stop|config)\s+windefend)", _I), 8, "T1562.001"),
    ("Firewall disabled", re.compile(r"netsh(\.exe)?\s.*advfirewall\s.*state\s+off", _I), 6, "T1562.004"),
    ("Local account creation / admin group change", re.compile(r"net1?(\.exe)?\s+(user\s+\S+\s+\S+\s+/add|localgroup\s+administrators\s+\S+\s+/add)", _I), 6, "T1136.001"),
    ("Scheduled task created from command line", re.compile(r"schtasks(\.exe)?\s.*/create", _I), 4, "T1053.005"),
    ("Run-key persistence via reg.exe", re.compile(r"reg(\.exe)?\s+add\s.*\\(currentversion\\run|winlogon)", _I), 5, "T1547.001"),
    ("Service created from command line", re.compile(r"\bsc(\.exe)?\s+(create|config)\s.*binpath", _I), 5, "T1543.003"),
    ("Clear event logs", re.compile(r"(wevtutil(\.exe)?\s+(cl|clear-log)|clear-eventlog)", _I), 7, "T1070.001"),
]

# Service ImagePaths that launch interpreters (PsExec / Metasploit style)
SERVICE_INTERPRETER_PATTERN = re.compile(
    r"(%comspec%|cmd(\.exe)?\s+/[ck]\s|powershell|pwsh|mshta|wscript|cscript|rundll32\.exe\s+\S*\.(txt|jpg|png|tmp)|regsvr32)",
    _I)

# ---------------------------------------------------------------------------
# Locations
# ---------------------------------------------------------------------------

# Directories attackers stage payloads in (high risk for any executable)
TEMP_LIKE_MARKERS = [
    "\\appdata\\local\\temp\\", "\\windows\\temp\\", "\\temp\\", "\\tmp\\", "\\users\\public\\",
    "\\downloads\\", "\\$recycle.bin\\", "\\perflogs\\", "\\windows\\tasks\\",
]
# User-profile locations legitimate software also uses (medium risk unless signed)
PROFILE_MARKERS = ["\\appdata\\roaming\\", "\\appdata\\local\\", "\\programdata\\"]
# Extra markers that are suspicious specifically for services / startup entries
STRICT_PROFILE_MARKERS = ["\\users\\"]

TRUSTED_ROOTS = ["c:\\windows\\", "c:\\program files\\", "c:\\program files (x86)\\"]

DOUBLE_EXTENSION = re.compile(r"\.(pdf|docx?|xlsx?|pptx?|txt|jpe?g|png|gif|zip|rar|mp3|mp4)\.(exe|scr|com|bat|cmd|pif)$", _I)

SYSTEM_ACCOUNTS = {
    "nt authority\\system", "nt authority\\local service", "nt authority\\network service",
    "localsystem", "nt authority\\localservice", "nt authority\\networkservice",
}
LOCALSYSTEM_NAMES = {"localsystem", "nt authority\\system"}

# ---------------------------------------------------------------------------
# MITRE ATT&CK technique id -> (name, tactic). Used whenever a rule reports a more specific
# technique than its catalog default, so the displayed name always matches the id.
# ---------------------------------------------------------------------------

TECHNIQUES = {
    "T1003": ("OS Credential Dumping", "Credential Access"),
    "T1003.001": ("OS Credential Dumping: LSASS Memory", "Credential Access"),
    "T1021.002": ("Remote Services: SMB/Windows Admin Shares", "Lateral Movement"),
    "T1027": ("Obfuscated Files or Information", "Defense Evasion"),
    "T1036": ("Masquerading", "Defense Evasion"),
    "T1036.004": ("Masquerading: Masquerade Task or Service", "Defense Evasion"),
    "T1036.005": ("Masquerading: Match Legitimate Name or Location", "Defense Evasion"),
    "T1036.007": ("Masquerading: Double File Extension", "Defense Evasion"),
    "T1047": ("Windows Management Instrumentation", "Execution"),
    "T1053.005": ("Scheduled Task/Job: Scheduled Task", "Persistence"),
    "T1055": ("Process Injection", "Defense Evasion"),
    "T1059": ("Command and Scripting Interpreter", "Execution"),
    "T1059.001": ("Command and Scripting Interpreter: PowerShell", "Execution"),
    "T1059.005": ("Command and Scripting Interpreter: Visual Basic", "Execution"),
    "T1068": ("Exploitation for Privilege Escalation", "Privilege Escalation"),
    "T1070": ("Indicator Removal", "Defense Evasion"),
    "T1070.001": ("Indicator Removal: Clear Windows Event Logs", "Defense Evasion"),
    "T1070.004": ("Indicator Removal: File Deletion", "Defense Evasion"),
    "T1105": ("Ingress Tool Transfer", "Command and Control"),
    "T1136.001": ("Create Account: Local Account", "Persistence"),
    "T1189": ("Drive-by Compromise", "Initial Access"),
    "T1197": ("BITS Jobs", "Defense Evasion"),
    "T1204": ("User Execution", "Execution"),
    "T1204.002": ("User Execution: Malicious File", "Execution"),
    "T1218.005": ("System Binary Proxy Execution: Mshta", "Defense Evasion"),
    "T1218.010": ("System Binary Proxy Execution: Regsvr32", "Defense Evasion"),
    "T1218.011": ("System Binary Proxy Execution: Rundll32", "Defense Evasion"),
    "T1490": ("Inhibit System Recovery", "Impact"),
    "T1505.003": ("Server Software Component: Web Shell", "Persistence"),
    "T1543": ("Create or Modify System Process", "Persistence"),
    "T1543.003": ("Create or Modify System Process: Windows Service", "Persistence"),
    "T1546.008": ("Event Triggered Execution: Accessibility Features", "Privilege Escalation"),
    "T1547.001": ("Boot or Logon Autostart Execution: Registry Run Keys / Startup Folder", "Persistence"),
    "T1553.002": ("Subvert Trust Controls: Code Signing", "Defense Evasion"),
    "T1562.001": ("Impair Defenses: Disable or Modify Tools", "Defense Evasion"),
    "T1562.004": ("Impair Defenses: Disable or Modify System Firewall", "Defense Evasion"),
    "T1569.002": ("System Services: Service Execution", "Execution"),
    "T1574.009": ("Hijack Execution Flow: Path Interception by Unquoted Path", "Privilege Escalation"),
    "T1574.010": ("Hijack Execution Flow: Services File Permissions Weakness", "Privilege Escalation"),
    "T1574.011": ("Hijack Execution Flow: Services Registry Permissions Weakness", "Privilege Escalation"),
}
