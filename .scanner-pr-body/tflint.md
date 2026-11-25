## feat(plugins): tflint alpha scanner plugin

### What it scans

TFLint over Terraform (`*.tf`, `*.tf.json`) with its bundled `terraform` ruleset: `tflint --format=sarif --recursive --chdir=<target> --config=<empty file ASH writes> --no-color`. It reports deprecated syntax, unused declarations, missing version constraints and naming conventions. `--init` is never run, so the network-fetched `aws`, `azurerm` and `google` rulesets are not used, and a `.tflint.hcl` in the scanned tree is not read.

### Tier

Alpha, opt-in. Loaded only when `ash_tflint_plugins` is listed in `ash_plugin_modules`. Module: `automated_security_helper/plugin_modules/ash_tflint_plugins/`.

### Facets declared

- `facets` (mapping register): rule id, severity, file path, line range, column and message are mapped. Tags and `issue_severity` extras are written by the adapter. `references` is declared mappable-but-dropped (`runs[0].tool.driver.rules[].helpUri`). Resource id and type, package fields, CVE and CWE, fingerprints, fix state, remediation text and snippet are n/a with reasons, read from the captured SARIF.
- `operational_facets`: no network (`BUNDLED`, strict sandbox), SARIF output, `IAC_TERRAFORM` target (tool type IaC), pinned binary, native severity, one repository-writable tool-side silencing layer (`# tflint-ignore:` comments, honored), positional-only identity, exit codes `{0, 2}`, community opt-in tier, template prerequisite.

### Fixed from the build review

- MUST: the plugin could not be constructed on main, because `pinned_tool_install_commands("tflint")` raises while `utils/tool_downloads.py` has no tflint rows. The module now leaves the install table empty in that case (the tool reads as not installable) and builds. Pinned test: `TestInstall::test_without_pin_rows_the_scanner_still_builds_and_cannot_install`; the full install-table test runs once the rows exist.
- MUST: the `tflint-errors` run was never refused. The base class stamps its own tool name on every run before `_post_process_sarif`, so the run read as a second `tflint` run and its diagnostics, which quote scanned source, would have been reported as findings. The error run is now refused or dropped in `_read_results_file`, on the report as TFLint wrote it. The two existing tests that pin this (`test_the_error_run_is_not_kept_when_empty`, `test_error_run_results_fail_the_scan_without_quoting_them`) failed before the change and pass after.
- Checklist row 18: severity mapping tested over a real captured report (`tests/test_data/scanners/tflint/captured/positive.sarif`, `negative.sarif`, a TFLint 0.66.0 run with the README beside them), plus the unknown-level row (`none` rates HIGH).
- Checklist row 24: captured fixtures committed with a README naming the binary, its sha256 and the flags.
- Checklist row 25: sandbox-requirements test (strict default, policy built with `build_scanner_policy`, no network).

### License posture

TFLint is MPL-2.0, and its release binaries embed `terraform` package files under BUSL 1.1; the README says the executable form is bound by both. ASH runs the binary as a separate process and never vendors or redistributes it. The design is deliberate: an install-on-demand from the pinned upstream release asset, no bundling.

### Central registration still owed (an integration lane serializes these; none is made here)

1. `utils/tool_downloads.py`: `TOOL_VERSIONS["tflint"] = "v0.66.0"`, the release base URL, the asset table (darwin/amd64, darwin/arm64, linux/amd64, linux/arm64, windows/amd64; no windows/arm64) and digest rows from the release `checksums.txt` (linux_amd64 `22be11ca...`, linux_arm64 `1105a0a5...`, darwin_amd64 `e2d98b60...`, darwin_arm64 `859b26af...`, windows_amd64 `e3acd1d8...`; all are zips), and a `THIRD_PARTY_LICENSES["tflint"]` entry.
2. `utils/scanner_names.py`: `SCANNER_TOOL_TYPES["tflint"] = "IAC"`.
3. Plugin-module inventories: `core/scanner_inventory.py` module list, `Dockerfile` `ASH_COMMUNITY_PLUGIN_MODULES`, `tests/unit/walked_package.py` `PACKAGE_DIRS` (`plugin_modules/ash_tflint_plugins`), the link-handling table in `tests/unit/plugin_modules/test_walking_scanners_skip_links_leaving_the_tree.py`, the corpus table in `test_scanner_facets_corpus_consistency.py`, the native-fixture table in `test_scanner_operational_facets_consistency.py` (`"tflint": ("tflint/captured/positive.sarif", SARIF)`), and the hard-coded "22 shipped scanners" counts in `test_scanner_facets_registry_totality.py` and `test_scanner_operational_facets_consistency.py`.

### Desk counts

dev-dsk-d14420e2, repository extract, `uv sync --frozen --all-extras --group dev`, `env -i`, `-n 4`, basetemp in the lane. Base: origin/main e0aac6c3aff.

- tflint module tests: all pass (included in tests/unit/plugin_modules: 8850 passed, 28 failed, 395 skipped).
- Facets families (registry totality, operational consistency, both vocabulary tests): every per-scanner row for TflintScanner passes except the two that need the central rows above (`test_tool_type_is_one_story...[TflintScanner]`, `test_platforms_are_derived_from_the_download_table[TflintScanner]`); the count tests, the corpus registry test, the link-handling test and the PACKAGE_DIRS gate fail only on the missing central registrations.
- The remaining failures (`test_actionlint_scanner.py`, `test_scanner_facets_corpus_consistency.py::test_declared_facets_agree_with_the_observed_corpus[*]`) fail identically on origin/main on that desk (baseline run: 30 failed in the same files).
- Whole-tree collect: 74309 collected, one collection error, the `PACKAGE_DIRS` gate naming `plugin_modules/ash_tflint_plugins`.
- ruff format --check and ruff check: clean.
