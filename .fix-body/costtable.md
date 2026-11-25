## Pre-commit cost table: rebuildable fixtures, one named venue

The "What it costs" table in the pre-commit how-to kept a ~900-file column from an earlier
measurement on a different machine, with no recorded repository and no way to rerun it.
This change makes both columns reproducible and labels the figures.

- `scripts/measure_precommit_cost.py` generates both repositories deterministically (10 files,
  and 900 files in 30 packages of 30 modules, with a few scanner-visible lines), makes each a
  one-commit git repository, and times the table's rows: median of three warm runs after one
  discarded warm-up, with min and max and the load average printed beside them. It also runs
  the express row and stops the daemon afterward.
- `tests/unit/scripts/test_measure_precommit_cost.py` pins the file counts and a SHA-256
  digest of each fixture's bytes (the same digests came out on this host and on the desk), a
  byte-for-byte rebuild, a planted one-byte change that moves the digest, the scanner-visible
  content counts, and that both doc pages name the script, the 900-file column and the date.
  It fails before the digests are filled in (2 failed, 5 passed on the desk) and passes after.
- Both pages (`pre-commit.md` and its `.template`) now carry figures from one session on one
  venue and say so: dev-dsk-d14420e2 (192 vCPU x86_64, Python 3.12.15, ASH v3.8.0, 2026-11-25),
  load average 140 to 750 during the runs, so the figures are upper bounds.

| Warm run | 10-file | 900-file |
|---|---|---|
| whole repository, no `--staged` | 14.9 s (14.3-17.6) | 13.6 s (13.5-14.4) |
| `--staged`, one `.py` staged | 7.7 s (7.2-7.9) | 5.1 s (4.9-5.2) |
| same, `--only-scanners bandit,detect-secrets` | 7.0 s (6.7-7.1) | 4.7 s (4.7-4.9) |
| `--staged --express`, daemon warm | 3.9 s (3.8-4.2) | 3.0 s (3.0-3.1) |

`ash --version` read 0.22 s on the same host. The 10-file column was timed first, while the
host was busiest, so the sizes are not comparable across columns; the page says so. The old
quiet-machine 10-file figures (6.6, 2.8, 2.8, 1.4 s) are dropped rather than kept beside
figures from a different venue.

### Verification

- Desk dev-dsk-d14420e2, repository extract, `uv sync --frozen --all-extras --group dev`,
  `env -i`, `tests/unit/scripts tests/unit/docs -n 8`: 885 passed, 673 skipped, 1 failed
  (`test_every_page_carries_a_doctest_mechanism_or_is_on_the_shrinking_allowlist`, on
  `deduplicate-findings.md`). The same id fails on main on the same desk (tests/unit/docs
  there: 387 passed, 1 failed), so the failing-id delta is 0.
- ruff check and ruff format --check: clean (the commit hooks ran both). Conflict-marker
  scan over the four touched files: 0, with a planted marker file reading 1.
- Desk extract removed; absence read back.

### Not done

- No claim test pins a timing figure; wall-clock time on a shared host is not stable enough
  to fail a build on, so the figures are labelled with venue and date instead.
- A quiet-machine rerun is still open; the script is what to run.
