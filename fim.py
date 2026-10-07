#!/usr/bin/env python3
"""
File Integrity Monitoring System (FIM)

Builds a baseline of SHA-256 hashes for every file in a directory, then
detects and alerts on modified, new, and deleted files.

Usage:i
    python fim.py init  <directory>              # create baseline
    python fim.py check <directory>              # one-time integrity check
    python fim.py watch <directory> [-i SECONDS] # continuous monitoring
"""

import argparse
import hashlib
import json
import logging
import os
import sys
import time
from datetime import datetime

BASELINE_FILE = "baseline.json"
LOG_FILE = "fim_alerts.log"
CHUNK_SIZE = 65536  # read files in 64 KB chunks (safe for large files)

# Never monitor the tool's own state files.
IGNORED = {BASELINE_FILE, LOG_FILE}

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[logging.FileHandler(LOG_FILE), logging.StreamHandler(sys.stdout)],
)
log = logging.getLogger("fim")


def sha256_file(path):
    """Return the SHA-256 hex digest of a file, or None if unreadable."""
    h = hashlib.sha256()
    try:
        with open(path, "rb") as f:
            while chunk := f.read(CHUNK_SIZE):
                h.update(chunk)
    except (PermissionError, FileNotFoundError, OSError) as e:
        log.warning("Cannot read %s: %s", path, e)
        return None
    return h.hexdigest()


def scan_directory(directory):
    """Walk a directory and return {relative_path: sha256_hash}."""
    hashes = {}
    for root, _, files in os.walk(directory):
        for name in files:
            if name in IGNORED:
                continue
            full = os.path.join(root, name)
            digest = sha256_file(full)
            if digest:
                hashes[os.path.relpath(full, directory)] = digest
    return hashes


def entries_digest(hashes):
    """Digest over the whole baseline, to detect tampering with baseline.json."""
    blob = json.dumps(hashes, sort_keys=True).encode()
    return hashlib.sha256(blob).hexdigest()


def save_baseline(hashes):
    data = {
        "created": datetime.now().isoformat(timespec="seconds"),
        "baseline_digest": entries_digest(hashes),
        "files": hashes,
    }
    with open(BASELINE_FILE, "w") as f:
        json.dump(data, f, indent=2)


def load_baseline():
    if not os.path.exists(BASELINE_FILE):
        log.error("No baseline found. Run: python fim.py init <directory>")
        sys.exit(1)
    with open(BASELINE_FILE) as f:
        data = json.load(f)
    if entries_digest(data["files"]) != data.get("baseline_digest"):
        log.critical("ALERT: baseline.json itself has been tampered with!")
        sys.exit(2)
    return data["files"]


def compare(baseline, current):
    """Return (modified, new, deleted) lists."""
    modified = [p for p in current if p in baseline and current[p] != baseline[p]]
    new = [p for p in current if p not in baseline]
    deleted = [p for p in baseline if p not in current]
    return modified, new, deleted


def report(modified, new, deleted):
    for p in modified:
        log.critical("ALERT: MODIFIED  %s", p)
    for p in new:
        log.warning("ALERT: NEW FILE  %s", p)
    for p in deleted:
        log.warning("ALERT: DELETED   %s", p)
    return bool(modified or new or deleted)


def cmd_init(directory):
    hashes = scan_directory(directory)
    save_baseline(hashes)
    log.info("Baseline created: %d files hashed -> %s", len(hashes), BASELINE_FILE)


def cmd_check(directory):
    baseline = load_baseline()
    changed = report(*compare(baseline, scan_directory(directory)))
    if not changed:
        log.info("OK: all %d files match the baseline.", len(baseline))
    return changed


def cmd_watch(directory, interval):
    baseline = load_baseline()
    log.info("Watching %s every %ss (Ctrl+C to stop)", directory, interval)
    reported = set()  # avoid repeating the same alert every cycle
    try:
        while True:
            current = scan_directory(directory)
            modified, new, deleted = compare(baseline, current)
            state = {("M", p, current[p]) for p in modified}
            state |= {("N", p, current[p]) for p in new}
            state |= {("D", p, None) for p in deleted}
            fresh = state - reported
            if fresh:
                report(
                    [p for k, p, _ in fresh if k == "M"],
                    [p for k, p, _ in fresh if k == "N"],
                    [p for k, p, _ in fresh if k == "D"],
                )
                reported |= fresh
            time.sleep(interval)
    except KeyboardInterrupt:
        log.info("Monitoring stopped.")


def main():
    parser = argparse.ArgumentParser(description="File Integrity Monitoring System")
    parser.add_argument("command", choices=["init", "check", "watch"])
    parser.add_argument("directory")
    parser.add_argument("-i", "--interval", type=int, default=5,
                        help="seconds between scans in watch mode (default 5)")
    args = parser.parse_args()

    if not os.path.isdir(args.directory):
        log.error("Not a directory: %s", args.directory)
        sys.exit(1)

    if args.command == "init":
        cmd_init(args.directory)
    elif args.command == "check":
        sys.exit(1 if cmd_check(args.directory) else 0)
    else:
        cmd_watch(args.directory, args.interval)


if __name__ == "__main__":
    main()
