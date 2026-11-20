#!/usr/bin/env python3
"""ShelfLife — a read-only, deterministic stale-file auditor.

Audits file age, size, emptiness, and temp residue across one or more
directory trees from metadata only and reports named findings. It
never opens file contents, never follows symlinks, and never changes
anything: it reports, a human decides.
"""
import argparse
import fnmatch
import json
import math
import os
import stat
import sys
import time

VERSION = "1.0.0"

SEVERITY_ORDER = {"low": 0, "medium": 1, "high": 2}

TEMP_PATTERNS = ("*.tmp", "*.temp", "*.bak", "*.old", "*.swp", "*~")

DEFAULT_STALE_DAYS = 365
DEFAULT_LARGE_BYTES = 104857600


def findings_for_file(path, st, now, stale_days, large_bytes):
    """Return (findings, is_stale) for one regular file stat result."""
    out = []
    size = st.st_size
    age_seconds = now - st.st_mtime
    if age_seconds < 0:
        age_seconds = 0
    age_days = int(age_seconds // 86400)
    is_stale = (now - st.st_mtime) >= stale_days * 86400
    is_large = size >= large_bytes
    base = os.path.basename(path).lower()
    if size == 0:
        out.append(("empty-file", "low"))
    if is_large:
        out.append(("large-file", "low"))
    if any(fnmatch.fnmatchcase(base, p) for p in TEMP_PATTERNS):
        out.append(("temp-residue", "medium"))
    if is_stale:
        out.append(("stale-file", "medium"))
    if is_large and is_stale:
        out.append(("large-stale", "high"))
    return out, is_stale, size, age_days


def scan(roots, now, stale_days, large_bytes):
    findings = []
    dirs_scanned = 0
    files_scanned = 0
    symlinks_skipped = 0
    errors = 0
    total_bytes = 0
    reclaimable_bytes = 0
    for root in roots:
        for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
            dirnames.sort()
            kept = []
            for name in dirnames:
                full = os.path.join(dirpath, name)
                if os.path.islink(full):
                    symlinks_skipped += 1
                else:
                    kept.append(name)
            dirnames[:] = kept
            try:
                st = os.lstat(dirpath)
            except OSError:
                errors += 1
                continue
            dirs_scanned += 1
            # Empty-dir: no subdirectories (after symlink pruning counts
            # as entries if present on disk) and no files on disk.
            try:
                entries = os.listdir(dirpath)
            except OSError:
                errors += 1
                entries = None
            if entries is not None and len(entries) == 0:
                age_seconds = now - st.st_mtime
                if age_seconds < 0:
                    age_seconds = 0
                age_days = int(age_seconds // 86400)
                findings.append({
                    "path": dirpath, "rule": "empty-dir", "severity": "low",
                    "size": 0, "age_days": age_days, "kind": "dir",
                })
            for name in sorted(filenames):
                full = os.path.join(dirpath, name)
                if os.path.islink(full):
                    symlinks_skipped += 1
                    continue
                try:
                    fst = os.lstat(full)
                except OSError:
                    errors += 1
                    continue
                if not stat.S_ISREG(fst.st_mode):
                    continue
                files_scanned += 1
                total_bytes += fst.st_size
                file_findings, is_stale, size, age_days = findings_for_file(
                    full, fst, now, stale_days, large_bytes)
                if is_stale:
                    reclaimable_bytes += size
                for rule, sev in file_findings:
                    findings.append({
                        "path": full, "rule": rule, "severity": sev,
                        "size": size, "age_days": age_days, "kind": "file",
                    })
    findings.sort(key=lambda f: (f["path"], f["rule"]))
    return {
        "findings": findings,
        "dirs_scanned": dirs_scanned,
        "files_scanned": files_scanned,
        "symlinks_skipped": symlinks_skipped,
        "errors": errors,
        "total_bytes": total_bytes,
        "reclaimable_bytes": reclaimable_bytes,
    }


def main(argv=None):
    parser = argparse.ArgumentParser(prog="shelflife")
    parser.add_argument("--version", action="version", version=f"shelflife {VERSION}")
    sub = parser.add_subparsers(dest="command")
    sp = sub.add_parser("scan")
    sp.add_argument("dirs", nargs="+")
    sp.add_argument("--json", action="store_true")
    sp.add_argument("--min-severity", choices=["low", "medium", "high"], default="low")
    sp.add_argument("--fail-on", choices=["low", "medium", "high", "never"], default="high")
    sp.add_argument("--stale-days", type=int, default=DEFAULT_STALE_DAYS)
    sp.add_argument("--large-bytes", type=int, default=DEFAULT_LARGE_BYTES)
    sp.add_argument("--now", type=float, default=None)
    args = parser.parse_args(argv)
    if args.command != "scan":
        parser.print_usage(sys.stderr)
        return 2
    if args.stale_days < 0:
        print("shelflife: --stale-days must be >= 0", file=sys.stderr)
        return 2
    if args.large_bytes <= 0:
        print("shelflife: --large-bytes must be > 0", file=sys.stderr)
        return 2
    for root in args.dirs:
        if not os.path.isdir(root) or os.path.islink(root):
            # A symlink root is treated as not a directory for safety:
            # scanning must start from a real directory.
            if not os.path.isdir(root):
                print(f"shelflife: scan root is not a directory: {root}", file=sys.stderr)
                return 2
    now = args.now if args.now is not None else time.time()
    result = scan(args.dirs, now, args.stale_days, args.large_bytes)
    min_rank = SEVERITY_ORDER[args.min_severity]
    filtered = [f for f in result["findings"] if SEVERITY_ORDER[f["severity"]] >= min_rank]
    counts = {"high": 0, "medium": 0, "low": 0}
    for f in filtered:
        counts[f["severity"]] += 1
    if args.json:
        payload = {
            "version": VERSION,
            "dirs_scanned": result["dirs_scanned"],
            "files_scanned": result["files_scanned"],
            "symlinks_skipped": result["symlinks_skipped"],
            "errors": result["errors"],
            "total_bytes": result["total_bytes"],
            "reclaimable_bytes": result["reclaimable_bytes"],
            "findings": filtered,
            "summary": {
                "findings": len(filtered),
                "high": counts["high"],
                "medium": counts["medium"],
                "low": counts["low"],
            },
        }
        print(json.dumps(payload, indent=2, sort_keys=True))
    else:
        for f in filtered:
            print(f"{f['severity'].upper():6} {f['rule']} {f['size']} {f['age_days']} {f['path']}")
        print(f"shelflife: {result['dirs_scanned']} dirs scanned, {result['files_scanned']} files, "
              f"{len(filtered)} findings ({counts['high']} high, {counts['medium']} medium, {counts['low']} low), "
              f"{result['reclaimable_bytes']} reclaimable bytes")
    if args.fail_on == "never":
        return 0
    fail_rank = SEVERITY_ORDER[args.fail_on]
    for f in filtered:
        if SEVERITY_ORDER[f["severity"]] >= fail_rank:
            return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
