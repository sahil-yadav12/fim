# File Integrity Monitoring System

A basic FIM tool in Python that detects unauthorized file changes using SHA-256 hashing.

**Skills:** Hashing, Cryptography | **Tech:** Python 3.8+, `hashlib` (standard library only)

## How it works
1. **Baseline** – every file in a directory is hashed with SHA-256 and stored in `baseline.json`.
2. **Compare** – later scans are compared with the baseline.
3. **Alert** – modified, new, and deleted files are reported to the console and `fim_alerts.log`.

SHA-256 has the avalanche property: changing a single bit of a file produces a completely different digest, so any tampering is detectable.

## Usage
```bash
python fim.py init  ./monitored        # create baseline
python fim.py check ./monitored        # one-time check (exit code 1 if changes)
python fim.py watch ./monitored -i 5   # continuous monitoring every 5 seconds
```

## Design notes
- Files are read in 64 KB chunks, so large files don't exhaust memory.
- The baseline carries its own digest, so tampering with `baseline.json` is detected.
- Watch mode de-duplicates alerts so the same change isn't reported every cycle.
- The tool's own files (`baseline.json`, `fim_alerts.log`) are excluded.

## Limitations / possible extensions
- Polling-based; could use `watchdog` for real-time OS events.
- The baseline digest is unkeyed; an attacker who can rewrite the baseline could recompute it. Use HMAC with a secret key, or store the baseline off-host, for stronger protection.
- Add email/Slack alerts, file permission and mtime tracking, and exclude patterns.