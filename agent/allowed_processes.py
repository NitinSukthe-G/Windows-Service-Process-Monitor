# Processes commonly expected on a Windows workstation.
# This is a starter allowlist and should be adjusted for the actual system.

ALLOWED_PROCESSES = {
    "system",
    "registry",
    "explorer.exe",
    "svchost.exe",
    "lsass.exe",
    "services.exe",
    "winlogon.exe",
    "csrss.exe",
    "smss.exe",
    "spoolsv.exe",
    "taskhostw.exe",
    "dwm.exe",
    "conhost.exe",
    "runtimebroker.exe",
    "searchhost.exe",
    "startmenuexperiencehost.exe",
    "sihost.exe",
    "fontdrvhost.exe",
    "ctfmon.exe",
    "cmd.exe",
    "powershell.exe",
    "python.exe",
}


def is_allowed_process(process_name):
    if not process_name:
        return False

    return process_name.lower() in ALLOWED_PROCESSES