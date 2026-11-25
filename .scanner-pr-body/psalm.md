## psalm alpha scanner plugin

Adds `ash_psalm_plugins`, an opt-in community scanner (alpha tier) that runs Psalm taint analysis over PHP files.

### What it scans

PHP files (`.php`, `.phtml`, `.inc`) under a psalm.xml that ASH generates in an empty directory under the results directory. The scan target is the only project directory, `vendor` and ASH output directories are ignored, and `--plugin` and `--init` are never passed, so a psalm.xml or autoloader in the scanned repository is not read. Results are SARIF written with `--report=...sarif`. By default only taint (`Tainted*`) results are kept; `options.include_type_issues` keeps Psalm's type and maintainability results too.

### Tier and runtime

- Tier: alpha, opt-in (listed in `ash_plugin_modules`).
- Runtime: the user's installed `psalm` and `php` (8.2 or newer). `validate_plugin_dependencies` needs both and reports the scanner MISSING otherwise.
- Sandbox: strict default (no network). `success_exit_codes = {0, 2}`; any other code fails the scan even if a report is on disk.
- Severity: taint at `error` is HIGH, taint at `note` is LOW, a kept type issue at `error` is MEDIUM and at `note` is INFO. The `issue_severity` property and the SARIF level always agree.

### Facets declared

`facets` (resource_id, resource_type and the package, CVE, fix and fingerprint cells are n/a; rule_id, severity, file_path, line_range, column and message are mapped; tags is mappable-but-dropped because the native result has no tags of its own; snippet, references, remediation_text and taxonomy_cwe are n/a with the reason "output not read; a sample run would settle it") and `operational_facets` (user-installed CLI, SARIF output, source-code target, derived severity, exit codes 0 and 2, community opt-in, no prerequisite).

### Findings fixed

The RESULTS row had no MUST or HIGH findings (verification was missing). One genuine defect was found by the desk run and fixed:

- `test_the_working_directory_is_the_source_directory` failed on current main: the base passes `cwd=None` to `_run_subprocess` and the test read that as a path. Psalm now runs in its generated config directory outside the scanned tree through `_subprocess_cwd`, and the test asserts that.

Also added: a severity-mapping test over a committed report, and declaration tests for the facets rows.

### License posture

Psalm is not downloaded or redistributed by this change. No install command ships until a pinned `psalm.phar` row exists (see below); `setup_custom_install_commands` tolerates its absence. The upstream license is recorded as "not read" in the provenance row because the repository has no entry for it.

### Fixture honesty

No PHP runtime was available when the plugin was written, so no real Psalm run is committed. `tests/test_data/scanners/psalm/handwritten/positive.sarif` is written by hand to the shape of Psalm's SARIF writer and says so in its README; a real capture would settle the n/a "output not read" cells.

### Central edits owed (integration lane)

Not made here, by design. Each is needed for the shared tests to pass with this module present:

1. `automated_security_helper/utils/scanner_names.py`: add `"psalm": "SAST"` to `SCANNER_TOOL_TYPES`.
2. `tests/unit/plugin_modules/test_scanner_facets_corpus_consistency.py`: add to `CORPORA`: `"psalm": CorpusSpec("psalm", sarif=("handwritten/*.sarif",)),` (verified over the fixture: every cell agrees).
3. The two "twenty-two shipped scanners" counts (`test_scanner_operational_facets_consistency.py::test_the_universe_is_the_twenty_two_shipped_scanners`, `test_scanner_facets_registry_totality.py::test_the_enumeration_holds_all_twenty_two_shipped_scanners`) and the corpus-table agreement test: 22 becomes 23 with this module (and more with the other alpha scanners).
4. `PACKAGE_DIRS`: name `plugin_modules/ash_psalm_plugins` (collection fails otherwise: "not named in PACKAGE_DIRS").
5. `utils/tool_downloads.py`: a `psalm` row (pinned `psalm.phar`) if ASH is to install it; then the runtime row moves from user-installed CLI to a pinned binary.

### Desk counts

dev-dsk-d14420e2, `uv sync --frozen --all-extras --group dev`, `env -i`, lane under /run/user/23503848, `-n 4`: psalm module tests, registry totality, resource-id conformance, operational consistency and both vocabulary families, 540 passed and 1 skipped with 3 failed, all three the central items 1 and 3 above. Corpus simulation with item 2 applied: all 20 psalm cells agree after the tags redeclaration. Whole-tree collect: 74316 collected with one error, the `PACKAGE_DIRS` item 4.
