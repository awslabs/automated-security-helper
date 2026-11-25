## ScanCode Toolkit scanner (alpha community plugin)

### What it scans

`ash_scancode_plugins` adds a community scanner that runs ScanCode Toolkit
(`scancode --license`) over the scan target and reports each license match as an INFO
finding (SARIF level `none`, `issue_severity` INFO), with the SPDX expression as the rule
id. It is a license and provenance inventory, not a vulnerability scanner. The scan makes
no network calls: the license index ships inside the `scancode-toolkit` package.

### Tier and opt-in

Alpha, community opt-in: the module is loaded only when `ash_scancode_plugins` is listed
in `ash_plugin_modules`. Once listed the scanner is enabled like other community scanners,
so `--scanners scancode` runs only it. (The commissioned build set `enabled: false`, which
made the documented one-run form a no-op: ASH runs a scanner only when it is both in the
allowlist and enabled.)

### Facets

Declares `facets` and `operational_facets` on the scanner class. Mapped: rule id,
severity (constant INFO), file path, line range, message, computed fingerprint
(`scancode/v1`), tags, extras. Dropped, with reasons: snippet (`--license-text` is never
passed) and references (`rule_url`). N/A, with reasons: column, resource id and type,
package fields (only `--license` runs), CVE and CWE taxonomy, fix state, remediation.
Operational: uv/PyPI runtime, bundled offline, constant severity, exit codes `{0}`,
`COMMUNITY_OPTIN` provenance, no tool-side silencing surface read.

### Fixed from the build review

- MUST: the documented one-run enablement was false (`enabled` defaulted False). Now True.
- HIGH: the stderr test could not fail. The scanner now uses the base `quote_tool_stderr =
  False` mechanism, and the test drives the real response handler with a planted control.
- HIGH, rows 18 and 24: captured real ScanCode 32.5.0 reports (positive, negative) plus
  `captured/README.md`, and tests converting them.
- HIGH, row 25: sandbox-requirements test through `build_scanner_policy`.
- HIGH, row 11: platform coverage declared in the operational facets, with a test.
- Found while capturing: with pluggy 1.7.0 every `scancode` command exits 1 at import, so
  an install following the old pin could not run. The install now adds `--with
  pluggy<1.7` (1.5.0 and 1.6.0 measured working).
- Row 3: the enabled-default deviation is removed by the MUST fix.

### License posture

ScanCode code is Apache-2.0; its reference data package is CC-BY-4.0 with LicenseRef
terms. ASH does not bundle or redistribute it: it is installed on request through `uv tool
install`. No vendoring.

### Central registration owed (integration lane)

Not made here, per the module-only scope. The registry tests currently read red for exactly
these reasons, all verified on the desk against a baseline without this module:

1. `automated_security_helper/utils/scanner_names.py`: add `"scancode"` to
   `SCANNER_TOOL_TYPES` with `"SCA"`.
2. `tests/unit/plugin_modules/test_scanner_facets_registry_totality.py` and
   `test_scanner_operational_facets_consistency.py`: shipped-scanner count 22 to 23 (and
   the operational consistency fixture entry for scancode if the table needs one).
3. `tests/unit/plugin_modules/test_scanner_facets_corpus_consistency.py`: add
   `"scancode": CorpusSpec("scancode", prep="scancode")` and a `_prep_scancode` that runs
   `convert_scancode_result(<captured/positive.json>, strip_first_segment="pos")`.
4. `tests/unit/walked_package.py`: add `plugin_modules/ash_scancode_plugins` to
   `PACKAGE_DIRS` (a whole-tree collection error otherwise).
5. The usual generated and shared rows (scanner inventory, config schema, docs index,
   coverage and CHANGELOG), as for the other community scanners.

### Desk validation (dev-dsk-d14420e2)

Shipped as a repository; `uv sync --frozen --all-extras --group dev`; `env -i`, `CI=1`,
lane under `/run/user/23503848/`, `-n 4`. The module's tests, the sandbox test, and the
facets registry, corpus, resource-id, operational and vocabulary families: 580 collected,
555 passed, 25 failed. 20 of the failures are in the facets corpus test for other scanners
and read identically with this module removed (baseline). The other 5 are the central
registration rows above. Whole-tree collect: 74311 tests collected, 1 error (row 4).
Module tests: all pass. ruff format and check green.

### Round 2 notes

- HIGH, facets-vs-register mismatch: fixed in this branch. `TargetsFacet.kinds` now declares
  `source_code` and `package_sources` (the SCA-served kind guarddog also uses), with a
  `tool_type_note`; pinned by `TestToolTypeIsServedByTheDeclaredKinds`. The central
  `SCANNER_TOOL_TYPES` entry (`"scancode": "SCA"`) stays owed to the integration lane;
  with that one entry applied on the desk, all 13 ScanCode operational-consistency cells pass,
  the one-story cell included.
- Test fix: the two end-to-end `scan()` capture tests ran over an empty directory, so `scan()`
  returned early with a bool; the target now holds a file.
- Desk result (module + facets families, ScanCode cells): 65 passed, 2 failed; both failures
  are the central rows (`SCANNER_TOOL_TYPES` KeyError, corpus prep for the captures).
- Final review, SHOULD (held, licensing): `provenance.upstream_license` reads
  `LICENSE_NOT_READ` while the docs page states Apache-2.0 code and CC-BY-4.0 data. Recording
  a license determination in the register needs explicit approval, so it is left as is.
