import os


SUSPICIOUS_DIRECTORIES = [
    "\\appdata\\local\\temp\\",
    "\\appdata\\roaming\\",
    "\\temp\\",
    "\\users\\public\\",
]


def normalize_path(path):
    if not path:
        return ""

    return path.lower().replace('"', "")


def is_suspicious_service_path(path):
    normalized = normalize_path(path)

    for directory in SUSPICIOUS_DIRECTORIES:
        if directory in normalized:
            return True

    return False