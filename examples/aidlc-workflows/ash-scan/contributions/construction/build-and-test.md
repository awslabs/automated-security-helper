---
target: build-and-test
plugin: ash-scan
fragments:
  - anchor: after-step:9
    order: 200
---

## fragment: after-step:9

### ash-scan: Run the full ASH scan

After the build and tests, run a full security scan of the project from its
root. Read the ASH version first, with `ash --version`, and run the scan as that
version spells it: ASH 3.9 added `ash scan fs`, and an ASH older than 3.9 refuses
that word with a usage error before it scans anything.

- 3.9 or later: `ash scan fs --no-progress`
- Older than 3.9: `ash scan --no-progress`

Unlike the per-Unit precommit scan, this runs every scanner the project's ASH
configuration enables, across all Units' changes at once, and writes its reports
to `.ash/ash_output/`.

Act on the exit code:

- 0: record "ASH scan: passed" in the build and test summary and continue.
- 2: actionable findings. Fix them, or, for an accepted risk, add a suppression
  under `global_settings.suppressions` in the project's ASH configuration, with
  the finding's `path`, `rule_id`, `line_start` and `line_end`, a `reason`, and
  an `expires` date, and rerun. List every suppression this intent added in the
  build and test summary, with its reason and expiry, so the human reviews them
  at the approval gate.
- 1: the scan is incomplete or a vulnerability database is stale. Install the
  missing tools with `ash dependencies install` and rerun. If a tool cannot run
  in this environment, exclude its scanner with `--exclude-scanners` and record
  the exclusion and its reason in the build and test summary: the summary must
  say what was not measured, not read as a clean scan.
- 3: the project's ASH configuration is invalid; `ash config validate` names
  the field. Fix it and rerun.
- 5: ASH did not accept the command line (a usage error), and its output names
  the option or value it refused. Nothing was scanned, so do not read findings
  from `.ash/ash_output/reports/ash.summary.md`: a file there is from an earlier
  run. Correct the command, in the spelling for this version above, and run it
  again. Do not proceed to the completion handoff until a scan has run.

Copy the scanner table from `.ash/ash_output/reports/ash.summary.md` into the
build and test summary, so the gate shows which scanners ran, which were
SKIPPED or MISSING, and the finding counts per severity. Do not proceed to the
completion handoff while the scan exits 1 or 2.
