"""Path and command-line helpers (pure functions, no OS access except env expansion)."""

import ntpath
import os
import re

from agent.rules_data import (
    PROFILE_MARKERS,
    STRICT_PROFILE_MARKERS,
    TEMP_LIKE_MARKERS,
    TRUSTED_ROOTS,
)

_EXE_RE = re.compile(r"^(.*?\.(?:exe|com|bat|cmd|scr|dll|sys))(?:\s|$)", re.IGNORECASE)


def norm(path):
    """Lower-case, backslash-normalised, quote-free path ('' for falsy input)."""
    if not path:
        return ""
    return str(path).replace('"', "").replace("/", "\\").strip().lower()


def expand(path):
    if not path:
        return ""
    expanded = os.path.expandvars(path)
    return expanded.replace("\??\\", "").replace("\systemroot\\", "c:\windows\\")


def parse_exe(command):
    """Return the executable path from a command line / service ImagePath."""
    if not command:
        return ""
    text = command.strip()
    if text.startswith('"'):
        end = text.find('"', 1)
        return expand(text[1:end] if end > 0 else text[1:])
    match = _EXE_RE.match(text)
    if match:
        return expand(match.group(1))
    return expand(text.split(" ")[0])


def is_unquoted_with_spaces(command):
    """True for ImagePaths such as: C:\Program Files\Vendor App\svc.exe -run"""
    if not command:
        return False
    text = command.strip()
    if text.startswith('"'):
        return False
    exe = parse_exe(text)
    if " " not in exe or "\\" not in exe:
        return False
    # an exe path that really contains a space, e.g. C:\Program Files\...
    return bool(_EXE_RE.match(text))


def directory(path):
    return ntpath.dirname(norm(path))


def display_dir(path):
    """Directory of a path keeping original case (for messages)."""
    return ntpath.dirname(str(path or "").replace('"', ""))


def basename(path):
    return ntpath.basename(norm(path))


def in_trusted_root(path):
    p = norm(path)
    return any(p.startswith(root) for root in TRUSTED_ROOTS)


def in_windows_dir(path):
    return norm(path).startswith("c:\windows\\")


def is_packaged_app(path):
    """Microsoft Store / MSIX apps: protected install dir, package-signed (not Authenticode-embedded)."""
    p = norm(path)
    return (p.startswith("c:\\program files\\windowsapps\\")
            or "\\appdata\\local\\microsoft\\windowsapps\\" in p)


def is_real_path(path):
    """True for drive-letter paths (psutil returns bare names such as 'MemCompression' for some kernel procs)."""
    return norm(path)[1:3] == ":\\"


def writable_tier(path, strict=False):
    """Classify a location: 'temp' (staging dirs), 'profile' (user profile) or None."""
    p = norm(path)
    if not p or is_packaged_app(p):
        return None
    # normalise so markers also match a path that ends in a marker directory
    probe = p if p.endswith("\\") else p + "\\"
    for marker in TEMP_LIKE_MARKERS:
        if marker in probe:
            return "temp"
    markers = PROFILE_MARKERS + (STRICT_PROFILE_MARKERS if strict else [])
    for marker in markers:
        if marker in probe:
            return "profile"
    return None


def levenshtein(a, b):
    if a == b:
        return 0
    if not a:
        return len(b)
    if not b:
        return len(a)
    previous = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        current = [i]
        for j, cb in enumerate(b, 1):
            current.append(min(previous[j] + 1, current[j - 1] + 1, previous[j - 1] + (ca != cb)))
        previous = current
    return previous[-1]
