# Suspicious parent-child process relationships

SUSPICIOUS_PARENT_CHILD = {
    "winword.exe": [
        "powershell.exe",
        "cmd.exe",
        "wscript.exe",
        "cscript.exe",
        "mshta.exe",
    ],
    "excel.exe": [
        "powershell.exe",
        "cmd.exe",
        "wscript.exe",
        "cscript.exe",
        "mshta.exe",
    ],
    "outlook.exe": [
        "powershell.exe",
        "cmd.exe",
        "wscript.exe",
        "cscript.exe",
        "mshta.exe",
    ],
    "powerpnt.exe": [
        "powershell.exe",
        "cmd.exe",
        "wscript.exe",
        "cscript.exe",
        "mshta.exe",
    ],
}


def is_suspicious_parent_child(parent_name, child_name):
    if not parent_name or not child_name:
        return False

    parent_name = parent_name.lower()
    child_name = child_name.lower()

    suspicious_children = SUSPICIOUS_PARENT_CHILD.get(parent_name, [])

    return child_name in suspicious_children