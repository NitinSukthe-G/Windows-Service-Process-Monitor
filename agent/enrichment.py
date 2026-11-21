"""File enrichment: SHA-256 hashing and Authenticode signature verification (cached)."""

import hashlib
import json
import logging
import os

from agent.collectors import run_json_script
from agent.config import BASELINE_DIR, ENRICHMENT_CACHE_FILE, MAX_HASH_BYTES

log = logging.getLogger("monitor.enrich")

SIG_VALID = "Valid"


def sha256_file(path):
    try:
        if os.path.getsize(path) > MAX_HASH_BYTES:
            return None
        digest = hashlib.sha256()
        with open(path, "rb") as handle:
            for chunk in iter(lambda: handle.read(1024 * 1024), b""):
                digest.update(chunk)
        return digest.hexdigest()
    except OSError:
        return None


def _signer_cn(subject):
    if not subject:
        return None
    for part in str(subject).split(","):
        part = part.strip()
        if part.upper().startswith("CN="):
            return part[3:].strip('"')
    return str(subject)[:80]


def _fingerprint(path):
    try:
        stat = os.stat(path)
        return f"{stat.st_size}:{int(stat.st_mtime)}"
    except OSError:
        return None


class Enricher:
    """Returns {lowercased_path: {sha256, sig_status, signer}} using an on-disk cache."""

    def __init__(self, check_signatures=True, cache_file=ENRICHMENT_CACHE_FILE):
        self.check_signatures = check_signatures
        self.cache_file = cache_file
        self.cache = self._load()

    def _load(self):
        try:
            with open(self.cache_file, encoding="utf-8") as handle:
                return json.load(handle)
        except (OSError, ValueError):
            return {}

    def _save(self):
        try:
            BASELINE_DIR.mkdir(parents=True, exist_ok=True)
            with open(self.cache_file, "w", encoding="utf-8") as handle:
                json.dump(self.cache, handle)
        except OSError as exc:
            log.warning("Could not write enrichment cache: %s", exc)

    def _verify_signatures(self, paths):
        rows = run_json_script("signature_check.ps1", paths)
        if rows is None:
            return {}
        return {row["path"].lower(): row for row in rows if row.get("path")}

    def enrich(self, paths):
        unique = {}
        for path in paths:
            if path and os.path.isfile(path):
                unique[path.lower()] = path

        pending_sig, result, changed = [], {}, False
        for key, path in unique.items():
            fingerprint = _fingerprint(path)
            cached = self.cache.get(key)
            same_file = bool(cached) and cached.get("fp") == fingerprint
            if same_file and (cached.get("sig_status") or not self.check_signatures):
                result[key] = cached
                continue
            entry = {
                "fp": fingerprint,
                "sha256": cached.get("sha256") if same_file and cached.get("sha256") else sha256_file(path),
                "sig_status": cached.get("sig_status") if same_file else None,
                "signer": cached.get("signer") if same_file else None,
            }
            result[key] = entry
            changed = True
            if self.check_signatures and not entry["sig_status"]:
                pending_sig.append(path)

        if pending_sig:
            log.info("Verifying %d new/changed signatures", len(pending_sig))
            for key, row in self._verify_signatures(pending_sig).items():
                if key in result:
                    result[key]["sig_status"] = row.get("status")
                    result[key]["signer"] = _signer_cn(row.get("signer"))

        if changed:
            self.cache.update(result)
            self._save()
        return result
