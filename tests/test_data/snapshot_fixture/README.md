# Snapshot fixture

The canonical input for the snapshot tests under `tests/snapshot`. Every reporter
snapshot, and every other snapshot that renders a scan result, is taken from this one
set of findings and scanner statuses, so a change to what ASH reports shows up as a diff
of the documents a user would open.

`tests/snapshot/support/fixture_model.py` turns it into an `AshAggregatedResults`
through ASH's own aggregation (`ScanResultProcessor.process_container`, the report
phase's final suppression pass and `populate_metrics_from_unified_source`). Its
docstring lists each step. The pytest fixtures `fixture_model`,
`fixture_workspace_model`, `fixture_skipped_workspace_model` and `fixture_variant` in
`tests/snapshot/conftest.py` are the way to use it from a test.

ASH's self-scan does not read this tree: `tests/test_data/**` is in the `ignore_paths`
of the repository's `.ash/.ash.yaml`. The code here is insecure on purpose and is never
executed.

## Why the scanner outputs are canned

Snapshots have to be identical on every machine and every run. Real scanner runs are
not: tool versions, rule sets and advisory databases change underneath them. So each
scanner's output is stored here in the form the scanner plugin hands to the scan phase
(SARIF, or CycloneDX for syft), with locations pointing into `repo/`. What is under
test is everything ASH does from that point on.

## The single-directory scan (`repo/`, `scanner_outputs/scanners.yaml`)

| Scanner | Outcome | Findings |
| --- | --- | --- |
| bandit | FAILED | B602 `shell=True` (HIGH, app/app.py:9), B105 hardcoded password (LOW, app/app.py:5) |
| checkov | FAILED | CKV_AWS_20 public-read ACL (HIGH), CKV_AWS_18 no access logging (MEDIUM), CKV_DOCKER_8 last USER is root (MEDIUM), CKV_DOCKER_2 no HEALTHCHECK (LOW) |
| grype | FAILED | CVE-2018-18074 in requests 2.19.1 (CRITICAL, from the rule's security-severity 9.8), CVE-2023-32681 (MEDIUM, 6.1) |
| semgrep | PASSED | last user is root (LOW), f-string shell command (INFO): both below the MEDIUM threshold |
| detect-secrets | PASSED | the password on app/app.py:5 (HIGH), suppressed by `repo/.ash/.ash.yaml` |
| syft | PASSED | SBOM with requests 2.19.1 and the python base image |
| cfn-nag | ERROR | attempted one target and failed on it |
| npm-audit | MISSING | dependencies not installed |
| cdk-nag | SKIPPED | excluded by the operator |

That covers every severity from CRITICAL to INFO, one suppressed finding, every scanner
status, and both a used and an unused suppression (`CKV_AWS_999` matches nothing, so
the unused-suppressions report lists it). The global severity threshold is MEDIUM.

## The workspace scans (`workspace/`, `scanner_outputs/workspace/`)

- `snapshot.code-workspace` lists two projects. `api` (threshold MEDIUM) has one HIGH
  bandit finding and a MISSING npm-audit. `web` (threshold HIGH) has one HIGH checkov
  finding and one MEDIUM semgrep finding below its threshold.
- `snapshot-with-skipped.code-workspace` adds a third folder, `docs`, which does not
  exist. Resolved with `allow_missing_projects`, it is recorded as a skipped project
  with reason `error`.

Both are run through `workspace.execution.execute_workspace` with only the per-project
orchestrator replaced, so the unified results file is the one ASH writes.

## Changing the fixture

Any change here changes snapshots across the suite. Update them with
`pytest tests/snapshot --snapshot-update`, read the diff, and commit it with a
`Snapshot-Update: <reason>` trailer. Keep the fixture small: a finding belongs here
only if it exercises a code path the existing ones do not.
