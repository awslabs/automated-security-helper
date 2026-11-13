## Security scanning habits

- Run the ASH scans at the stage checkpoints this plugin adds: the
  precommit-mode scan before a Unit's completion handoff, and the full scan at
  Build and Test. Read the exit code before moving on; do not add extra
  full-repository scans between the checkpoints.
- Exit code 2 is work, not noise: fix the finding, or record a suppression with
  a `reason` and an `expires` date under `global_settings.suppressions` in the
  project's ASH configuration. Never turn off `fail_on_findings` to get past a
  finding.
- Exit code 1 means the scan did not finish. Say which scanner was MISSING or
  ERROR instead of rerunning and hoping; `ash dependencies install` installs
  the scanner tools.
- Treat `.ash/ash_output/` as generated output: read the reports in it, never
  commit it, and never edit a report to change a result.
- Every suppression added during a workflow is listed in the stage summary that
  carries it to the human approval gate.
