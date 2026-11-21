"""Central configuration: paths, tunables and user-supplied rule overrides."""

import json
from pathlib import Path

VERSION = "2.0.0"

PROJECT_ROOT = Path(__file__).resolve().parents[1]
REPORT_DIR = PROJECT_ROOT / "reports"
DEMO_REPORT_DIR = REPORT_DIR / "demo"
LOG_DIR = PROJECT_ROOT / "logs"
BASELINE_DIR = PROJECT_ROOT / "baseline"
CONFIG_DIR = PROJECT_ROOT / "config"
PS_DIR = Path(__file__).resolve().parent / "powershell"

BASELINE_FILE = BASELINE_DIR / "baseline.json"
ENRICHMENT_CACHE_FILE = BASELINE_DIR / "enrichment_cache.json"
CUSTOM_RULES_FILE = CONFIG_DIR / "custom_rules.json"
IOC_HASH_FILE = CONFIG_DIR / "ioc_hashes.txt"

DEFAULT_INTERVAL_SECONDS = 10
DEEP_SCAN_EVERY_N_CYCLES = 6      # services / startup / tasks cadence in --watch
POWERSHELL_TIMEOUT_SECONDS = 600
MAX_HASH_BYTES = 150 * 1024 * 1024
MAX_HISTORY_LINES = 500

_DEFAULT_CUSTOM = {
    "allowed_processes": [],
    "blacklisted_processes": [],
    "trusted_service_names": [],
    "suppressions": [],
}


def load_custom_rules(path=CUSTOM_RULES_FILE):
    """Load analyst overrides (extra allow/deny entries and suppressions)."""
    data = {key: list(value) for key, value in _DEFAULT_CUSTOM.items()}
    try:
        loaded = json.loads(Path(path).read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return data
    for key in data:
        value = loaded.get(key)
        if isinstance(value, list):
            data[key] = value
    return data


def load_ioc_hashes(path=IOC_HASH_FILE):
    """Load known-bad SHA-256 hashes (one per line, '#' comments allowed)."""
    hashes = set()
    try:
        for line in Path(path).read_text(encoding="utf-8").splitlines():
            line = line.split("#", 1)[0].strip().lower()
            if len(line) == 64:
                hashes.add(line)
    except OSError:
        pass
    return hashes
