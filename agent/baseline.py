"""Baseline snapshot of services, startup entries and scheduled tasks for drift detection."""

import json
import logging
from datetime import datetime

from agent.config import BASELINE_DIR, BASELINE_FILE
from agent.persistence_rules import startup_key, task_key

log = logging.getLogger("monitor.baseline")


def build_baseline(snapshot):
    return {
        "created": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "services": {
            s["name"]: {k: s.get(k) for k in ("path", "start_mode", "start_name", "display_name")}
            for s in snapshot.get("services", []) if s.get("name")
        },
        "startup": {startup_key(e): e.get("command") for e in snapshot.get("startup", [])},
        "tasks": {task_key(t): t.get("command") for t in snapshot.get("tasks", [])},
    }


def load_baseline(path=BASELINE_FILE):
    try:
        with open(path, encoding="utf-8") as handle:
            data = json.load(handle)
        if isinstance(data, dict) and "services" in data:
            return data
    except (OSError, ValueError):
        pass
    return None


def save_baseline(baseline, path=BASELINE_FILE):
    BASELINE_DIR.mkdir(parents=True, exist_ok=True)
    with open(path, "w", encoding="utf-8") as handle:
        json.dump(baseline, handle, indent=2)
    return path
