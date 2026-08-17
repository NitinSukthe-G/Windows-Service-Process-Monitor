SUSPICIOUS_PATHS = [
    "\\appdata\\local\\temp\\",
    "\\appdata\\roaming\\",
    "\\temp\\",
    "\\users\\public\\",
    "\\downloads\\",
]


def normalize_path(path):
    if not path:
        return ""

    return path.lower().replace('"', "")


def is_suspicious_path(path):
    normalized = normalize_path(path)

    for suspicious_path in SUSPICIOUS_PATHS:
        if suspicious_path in normalized:
            return True

    return False