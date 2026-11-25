feat(mobsfscan): add the mobsfscan alpha scanner plugin

## What it scans

[mobsfscan](https://github.com/MobSF/mobsfscan) is a static analysis tool for Android
(Java, Kotlin), iOS (Swift, Objective-C) and mobile JavaScript source. ASH runs it as a
separate process, installed as a uv tool (`mobsfscan==1.2.0`), with
`--sarif --no-fail` and an empty stub config, and never imports it. It is a SAST
scanner over the source target.

## Tier

Alpha, opt-in: it loads only when `automated_security_helper.plugin_modules.ash_mobsfscan_plugins`
is listed in `ash_plugin_modules`. A scan that does not list it is unchanged.

## Facets declared

Both register rows are declared on the class: `facets` (the 20-facet row) and
`operational_facets` (the 13 operational dimensions).

* Mapped: rule id, severity, file path, line range, column, message, snippet, CWE
  taxonomy (read from the result properties and rule tags; 16 of 16 results in the
  capture), extras.
* Mappable but dropped: remediation text (rule help), references (rule `helpUri`),
  tags (rule tags). The severity facet is `degraded`: the `security-severity` score is
  not read.
* N/A with reasons: resource id and type (file:line locators), package name, version
  and path, CVE, fingerprints (the native result has none), fix state.
* Operational: network none (rules ship in the package, offline strategy BUNDLED),
  native format SARIF, source-code targets, uv-python runtime (needs `semgrep`),
  positional-only identity, success exit codes `{0}`, community opt-in tier.

## Findings fixed

From the build program's results row for this scanner:

* HIGH, scan-path tests could not pass without a real mobsfscan on PATH: the tests now
  stub `validate_plugin_dependencies`, so they run on every platform.
* HIGH, no captured fixtures (checklist rows 18 and 24): `tests/test_data/scanners/mobsfscan/captured/`
  holds positive, negative and semgrep-missing captures from a real mobsfscan 1.2.0
  run, with input trees and a README. The severity mapping is pinned row by row over
  the capture (`error` to HIGH, absent level to MEDIUM, `note` to LOW). The capture
  corrected a premise: mobsfscan omits `level` for a WARNING rule, so MEDIUM is the
  common case, and the six Android best-practice notes appear on every tree.
* HIGH, no sandbox-requirements test (row 25): `tests/unit/plugin_modules/test_mobsfscan_sandbox_requirements.py`.
* HIGH, silent false-clean path: when `semgrep` is not on PATH, mobsfscan exits 0 and
  its SARIF holds no Java, Kotlin or Swift finding and no error (the error is only in
  its JSON). Reproduced and captured. Through `uv tool run` semgrep is on PATH; for a
  pre-installed copy the scanner puts the tool environment's `bin` first on PATH and
  refuses the run when semgrep is still missing. Documented limit: per-file semgrep
  errors stay invisible in SARIF.

No MUST rows were recorded for this scanner.

## License posture

mobsfscan is LGPL-3.0-or-later. It is run as a separate process and is neither
imported nor redistributed, and no license-gate row records a restriction on it, so the
install stays a plain `uv tool install`.

## Central registration still owed

None of these is in this PR (an integration lane serializes them). With them applied in
a scratch copy, the facets families went green apart from 20 corpus-consistency failures
that also fail on main.

* `automated_security_helper/utils/scanner_names.py`, `SCANNER_TOOL_TYPES`: add `"mobsfscan": "SAST",`
* `automated_security_helper/core/scanner_inventory.py`, `_VENDORED_SCANNER_PLUGIN_PACKAGES`: add `"automated_security_helper.plugin_modules.ash_mobsfscan_plugins",`
* `tests/unit/walked_package.py`, `PACKAGE_DIRS`: add `"plugin_modules/ash_mobsfscan_plugins",`
* `tests/unit/plugin_modules/test_scanner_facets_corpus_consistency.py`, `CORPORA`: add
  `"mobsfscan": CorpusSpec("mobsfscan", sarif=("captured/positive.sarif", "captured/negative.sarif")),`
* the scanner count `22` becomes `23` in `test_scanner_facets_corpus_consistency.py`,
  `test_scanner_facets_registry_totality.py` and `test_scanner_operational_facets_consistency.py`
* the community plugin lists carry the module path as for guarddog
  (`.ash/.ash_community_plugins.yaml`, the Dockerfile `ASH_COMMUNITY_PLUGIN_MODULES`
  arguments, the CI workflow and `validate-container` plugin lists), if the scanner is to
  ship in the image

## Desk validation

dev-dsk-d14420e2, a repository extract, `uv sync --frozen --all-extras --group dev`,
`env -i`, CPython 3.12.15, `-n 4`, base `e0aac6c3aff`:

* the module's tests plus the sandbox-requirements test: 51 passed, 0 failed
* with the registration edits above applied in a scratch copy: facets registry
  totality, resource-id conformance, operational consistency, corpus consistency and the
  list-scanners import-order tests: 528 passed, 1 skipped, 20 failed; the same 20
  corpus-consistency tests (every other scanner) fail on main without this change
* without the registration edits: 5 additional failures, all the central one-liners
  above (three scanner counts, the tool-type table, the corpus table row)
* whole-tree collection: 72849 tests collected, no error (with the `PACKAGE_DIRS` edit)
* `ruff format --check` and `ruff check` pass
