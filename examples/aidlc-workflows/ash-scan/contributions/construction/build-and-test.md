---
target: build-and-test
plugin: ash-scan
fragments:
  - anchor: after-step:9
    order: 200
---

## fragment: after-step:9

### Step 9b (ash-scan): Run the full ASH scan

After the build and tests, run a full security scan of the project from its
root: `ash scan --no-progress`. Unlike the per-Unit precommit scan, this runs
every scanner the project's ASH configuration enables, across all Units'
changes at once, and writes its reports to `.ash/ash_output/`.

Act on the exit code:

- 0: record "ASH scan: passed" in the build and test summary and continue.
- 2: actionable findings. Fix them, or, for an accepted risk, add a suppression
  with a `reason` and an `expires` date under `global_settings.suppressions`
  in the project's ASH configuration and rerun. List every suppression this
  intent added in the build and test summary, with its reason and expiry, so
  the human reviews them at the approval gate.
- 1: the scan is incomplete or a vulnerability database is stale. Install the
  missing tools with `ash dependencies install` and rerun. If a tool cannot run
  in this environment, exclude its scanner with `--exclude-scanners` and record
  the exclusion and its reason in the build and test summary: the summary must
  say what was not measured, not read as a clean scan.
- 3: the project's ASH configuration is invalid; `ash config validate` names
  the field. Fix it and rerun.

Copy the scanner table from `.ash/ash_output/reports/ash.summary.md` into the
build and test summary, so the gate shows which scanners ran, which were
SKIPPED or MISSING, and the finding counts per severity. Do not proceed to the
completion handoff while the scan exits 1 or 2.
