# ShelfLife

A read-only, deterministic stale-file auditor in a single Python
file. ShelfLife walks one or more directory trees, checks file age,
size, emptiness, and temp residue against a small set of named rules,
and reports exactly what it found — it never deletes or changes
anything.

Downloads, build trees, backups, and shared folders silently
accumulate files that have outlived their shelf life: a 400-day-old
installer, an empty placeholder, a leftover `.bak`. The usual answers
are a destructive `find -delete` one-liner or a heavy disk GUI.
ShelfLife makes the audit visible and reproducible first, so a human
can decide what — if anything — to reclaim.

## Why it's different

- **Read-only by construction.** No `--delete`, no `--fix`, no writes
  of any kind. It reports; you decide.
- **Metadata-only.** Decisions use stat results (size, modification
  time, name) only. File contents are never opened.
- **Reclaimable honesty.** Reclaimable bytes count each stale file
  once, even when it matches several rules at once.
- **Reproducible age.** `--now` pins the reference time, so CI
  fixtures and reviews do not rot with the calendar.
- **Symlink-safe.** Symlinks are counted and never followed — no
  loops, no escaping the scanned tree through a link.
- **Deterministic.** Sorted walk and sorted findings; repeated
  `--json` runs are byte-identical, so output diffs cleanly in CI
  and in code review.

## Rules

| Rule | Severity | Meaning |
|---|---|---|
| `empty-file` | low | Regular file with size 0 |
| `empty-dir` | low | Directory with no entries at all |
| `large-file` | low | Regular file with size >= `--large-bytes` |
| `temp-residue` | medium | File name matches `*.tmp`, `*.temp`, `*.bak`, `*.old`, `*.swp`, or `*~` |
| `stale-file` | medium | File whose modification time is at least `--stale-days` old |
| `large-stale` | high | File that is both large and stale |

One path can produce several findings, one per rule. Reclaimable
bytes are the summed sizes of distinct stale files, computed from
the full stale set regardless of `--min-severity` filtering.

## Install

Nothing to install. Python 3.10+ and its standard library only.

```sh
python3 shelflife.py --version
```

## Usage

```sh
python3 shelflife.py scan DIR [DIR ...] [--json] \
    [--min-severity low|medium|high] \
    [--fail-on low|medium|high|never] \
    [--stale-days N] [--large-bytes N] [--now EPOCH]
```

Defaults: `--stale-days 365`, `--large-bytes 104857600` (100 MiB),
`--now` is the current time, and `--fail-on` defaults to `high`:
the scan exits 1 when any finding is at or above that severity.
`--min-severity` filters what is reported and counted.

### Example

A tree containing one 150-byte file named `big.bin`, last modified
400 days before the pinned reference time, scanned with
`--stale-days 365 --large-bytes 100 --now 1700000000`:

```text
$ python3 shelflife.py scan /tmp/sl-demo --now 1700000000 --stale-days 365 --large-bytes 100
LOW    large-file 150 400 /tmp/sl-demo/big.bin
HIGH   large-stale 150 400 /tmp/sl-demo/big.bin
MEDIUM stale-file 150 400 /tmp/sl-demo/big.bin
shelflife: 1 dirs scanned, 1 files, 3 findings (1 high, 1 medium, 1 low), 150 reclaimable bytes
(exit code 1, because a high finding meets the default --fail-on high)
```

## Exit codes

- `0` — scan completed; no finding at or above `--fail-on`
- `1` — at least one finding at or above `--fail-on`
- `2` — usage error or a scan root that is missing / not a directory

## Limitations

- Metadata only: a file that is old but still needed looks exactly
  like a file that is old and forgotten. ShelfLife reports age and
  size; it does not judge importance.
- Name patterns for `temp-residue` are heuristics — a deliberate
  `.bak` backup will match. Treat a finding as a prompt to look,
  not as a proof that a file is disposable.
- Modification time is the only age signal. Access time is not used
  (it is unreliable on many mounts).
- Unreadable directories are counted in `errors` and the scan
  continues past them.

## Tests

```sh
python3 -m unittest -v
```

16 tests covering every rule, reclaimable-once accounting, symlink
handling, determinism, read-only behavior, severity filtering,
future-mtime handling, and exit codes.

## License

MIT — see `LICENSE`. © 2026 Dimon Global Group.
