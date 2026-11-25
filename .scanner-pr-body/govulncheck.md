feat(plugins): govulncheck alpha scanner plugin

## What it scans

govulncheck (golang.org/x/vuln, BSD-3-Clause) reads each Go module in the tree (one run per directory holding a `go.mod`), matches the modules in use against the Go vulnerability database, and reports whether the vulnerable symbol is reachable. SARIF is read from stdout (the tool has no report-file flag), validated, merged across modules and written to the results directory.

## Tier

Alpha, opt-in: listed through `ash_plugin_modules`. Tool is user-installed (`go install` of the pinned `v1.9.0` module version into ASH's bin directory, linux and darwin, needs a Go toolchain). Skipped under `--offline` (the database is fetched at scan time). Network sandbox grant, Go caches read-only, `GO*` env passed.

## Facets declared

Mapping register (`facets`): every cell is n/a. No real govulncheck output exists in the repository (no Go toolchain was available where this was built), and the register refuses a MAPPED cell with no corpus to observe, so each unread cell says "output not read; a sample run would settle it". The adapter carries ruleId, the go.mod location, message, tags and the `issue_severity` it writes; a capture moves those to MAPPED.

Operational register (`operational_facets`): content fetch of the vuln database and module sources, offline not_run / skip_offline, sandbox network online, SARIF output, dependency manifest target (SCA), user-installed CLI needing `go`, per-module invocation, native severity, no tool-side silencing layer, identity unconfirmed, no custom rules, success exit codes (0,), community opt-in, prerequisite: go.mod. Upstream license is recorded as `not read` (no pinned upstream LICENSE read was made here).

## Fixed from the build review

- HIGH (no captured fixture; the test oracle is hand-written SARIF): not fixable here. No Go toolchain on the desk (`go` absent, toolchain frozen), so a real capture could not be made. The test module still says plainly that its SARIF is hand-written. Open: capture on a Go-equipped venue, add `tests/test_data/scanners/govulncheck/captured/` with a README (argv, version, inputs), add a `CORPORA` row, and move the facets cells to MAPPED. Checklist rows 18 and 24 stay unmet for that reason.
- Checklist row 25 (sandbox test): added `tests/unit/plugin_modules/test_govulncheck_sandbox_requirements.py` (network grant online and never offline, Go cache paths, `GO` env prefix pass-through).
- No failing committed tests and no raising install command were found: the module's 36 tests and the install tests pass on the desk.
- Deliberate and kept: no-gate design (BSD-3-Clause, public unauthenticated database); offline path fails toward SKIPPED.

## Central registration still owed (integration lane)

None of these were made here (module, its tests and its facets only). Exact edits, found by running the suites with the module present:

1. `automated_security_helper/utils/scanner_names.py` `SCANNER_TOOL_TYPES`: add `"govulncheck": "SCA",`.
2. `tests/unit/plugin_modules/test_scanner_facets_corpus_consistency.py`: add `"govulncheck": None,` to `CORPORA` and `"govulncheck": "no captured govulncheck output",` to `_NO_FIXTURE_DIRECTORY`; the scanner-count assertion (22) rises by one.
3. `tests/unit/plugin_modules/test_scanner_facets_registry_totality.py` and `test_scanner_operational_facets_consistency.py`: scanner-count assertion 22 -> +1; the offline-skipping list in the latter becomes `["govulncheck", "npm-audit", "snyk-code"]`.
4. `tests/unit/walked_package.py`: add `"plugin_modules/ash_govulncheck_plugins",` beside the guarddog entry (otherwise whole-tree collection fails with "not named in PACKAGE_DIRS").
5. Same registration points betterleaks has: `Dockerfile` `ASH_COMMUNITY_PLUGIN_MODULES` (two ARGs), `automated_security_helper/core/scanner_inventory.py`, `.ash/.ash_community_plugins.yaml`, the scan workflow module list, CHANGELOG.

## Desk validation (dev-dsk-d14420e2, extract as a repository, `uv sync --frozen --all-extras --group dev`, env -i, -n 4)

With the central edits above applied to the extract only: 39 passed in the govulncheck module and sandbox tests; facets totality, resource-id conformance, operational consistency all green for govulncheck; corpus consistency green for govulncheck. Twenty other scanners' corpus-consistency tests (tags/package columns observed empty) fail identically on the desk and are not this module's. Whole-tree collect: 74342/74387 collected, no errors. Extract removed and absence read back.
