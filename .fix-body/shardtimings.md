## Refresh the shard timings from a green run on main

### What changed

- `tests/utils/shard_timings.json` is regenerated with `scripts/update_shard_timings.py` from the
  `test-results-*` artifacts of Unified CI run 44831969283 on main at f5d774a2 (green, 2026-11-20).
  The previous file came from a PR head run (44383031131 on #956). Each (platform, tier) now
  averages five Python versions instead of three. Modules listed per tier grow from 426 to 874
  (linux unit), 254 to 330 (linux integration), 518 to 900 (macos unit), 282 to 352 (macos
  integration), 845 to 911 (windows unit) and 229 to 231 (windows integration); the added ones
  were hash-placed until now and are packed by seconds.
- `scripts/update_shard_timings.py` wrote the file with a one-space indent and unsorted keys.
  The repository's `pretty-format-json` hook sorts keys and indents by two, so the first commit of
  any refresh rewrote all 6,600 lines of the file. The script now writes the hook's form; the
  regenerated file is byte-identical to what the hook produces, and a test pins it.
- No staleness warning. The file has no date field (the `sources` strings are prose), so a check
  would need a schema change or git history, and a wall-clock test would fail or warn on a day
  nobody touched the code. `tests/unit/test_shard_plan.py` already says freshness is a
  maintainer's call and never a failure; a nudge nobody can act on in the PR that trips it is noise.

### Wall-clock effect

Before (measured): the same run's per-shard job durations, which ran under the old file. Within one
(runner, Python) group the slowest and fastest shard differ by 3 to 6 minutes on most groups, for
example ubuntu-latest unit py3.10 7.0 to 12.4 min, windows-latest unit py3.10 7.2 to 14.4 min,
ubuntu-latest integration py3.11 7.8 to 13.2 min. Job time includes setup and runner variance.

After (simulated, same measured per-module and per-test seconds, old plan against new plan).
Slowest shard's test seconds, mean over the five Python versions, with the even share for reference:

| platform / tier | old file | new file | even share |
|---|---|---|---|
| linux integration | 3881 | 3538 | 3410 |
| linux unit | 3133 | 2793 | 2622 |
| macos integration | 2825 | 2545 | 2413 |
| macos unit | 2286 | 1965 | 1824 |
| windows integration | 1807 | 1521 | 1461 |
| windows unit | 2177 | 1881 | 1765 |

The slowest shard drops 9 to 15 percent in every tier, and its excess over a perfectly even
split falls from roughly 14 to 24 percent to 4 to 8 percent. These numbers are in-sample: the
new file is scored on the data it was built from. A fresh CI run on the first PR that carries
this change is the out-of-sample measurement; the file changes no coverage either way (modules
the file does not list still go to their hash shard).

### Verification

- Red first: the new script test fails against the old script (desk d14420e2, `--run-integration`).
- `tests/unit/test_shard_plan.py` and `tests/unit/test_unit_test_shards.py`, `-n 8`, `env -i`,
  same desk: base 366 passed, branch 367 passed, failing-id delta 0.
- ruff format --check and ruff check over the tree pass; conflict-marker scan zero with a
  planted control; one noreply identity on every commit of the range.
