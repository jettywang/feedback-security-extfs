# Structure-aware fuzzing for `dissect.extfs`

This package fuzzes the ext2/ext4 parser with images that mutate real
filesystem structures instead of flipping arbitrary leading bytes. Its goal is
to find malicious images that stall or confuse a forensic worker.

## Layout

- `image_builder.py` — pure-Python synthesizer of small, parser-accepted ext2
  and ext4 seed images (no `mkfs.ext4` dependency). The ext4 seed contains a
  depth-1 extent index node; the ext2 seed uses direct/indirect block maps.
- `mutators.py` — structure-aware mutators. Each one rewrites a named field at
  its real on-disk offset: superblock geometry, feature flags, group
  descriptor pointers, inode sizes/flags, extent headers/leaves/child nodes,
  indirect block maps, directory entries, plus correlated multi-structure and
  self-referential extent-tree mutations. Mutators copy their input, so every
  case is replayable.
- `harness.py` — budgeted execution and classification.
- `control_samples.py` — deterministic controls with known expected outcomes,
  proving the detector actually alarms.
- `fuzzer.py` — fixed-seed campaign generation, gzip artifact persistence,
  replay and delta-debugging reduction.
- `__main__.py` — command-line entry point.

## Budgets and outcomes

Every case runs under two budgets:

- **read budget** — `GuardedFile` rejects reads/seeks outside the image and
  caps total bytes read (default 1 MiB).
- **time budget** — a `SIGALRM` watchdog interrupts non-terminating work
  (default 2 s).

Results fall into exactly one class, so an exception is never silently treated
as safe:

| Outcome     | Meaning                                                        | Safe? |
|-------------|----------------------------------------------------------------|-------|
| `rejected`  | documented format/value error (`Error`, `EOFError`, `ValueError`, `NotImplementedError`) | yes |
| `oob`       | read/seek outside the image or read budget exceeded            | no    |
| `timeout`   | wall-clock budget exhausted (non-termination)                  | no    |
| `bug`       | any other exception, e.g. `RecursionError`, `KeyError`, `IndexError` | no |
| `ok`        | parsed and read cleanly                                        | yes   |

## Controls

`control_samples.py` ships controls that must fire each alarm:

- self-referential extent tree -> `bug` (`RecursionError`, worker-stall class),
- extent child pointer past the image -> `oob`,
- corrupted superblock magic -> `rejected` (negative control),
- direct watchdog loop -> confirms the `timeout` path interrupts.

## Usage

Run the fixed-seed batch under pytest:

```
python -m pytest tests/test_fuzz_extfs.py
```

CLI:

```
python -m tests.fuzz run --seed 20261113 --cases-per-mutator 2 --out fuzz-out
python -m tests.fuzz replay fuzz-out/<artifact>.gz
python -m tests.fuzz reduce fuzz-out/<artifact>.gz --out reduced.gz
```

The same seed always produces byte-identical cases. Failing cases are stored as
self-describing gzip artifacts (magic `EXTFuzzV1`, JSON metadata, raw image) and
the reducer zeroes non-load-bearing bytes while preserving the failure class.
