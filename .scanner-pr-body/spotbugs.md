## SpotBugs scanner (alpha, opt-in)

Adds `ash_spotbugs_plugins`, a community scanner plugin that runs SpotBugs with the Find Security Bugs plugin over compiled JVM code (`.class` roots and `.jar`, `.war`, `.ear` archives) in the scan target. A tree with no bytecode is skipped quietly (INFO, not an error); ASH compiles nothing.

### Tier and enabling

Alpha, opt-in. The scanner loads only when `automated_security_helper.plugin_modules.ash_spotbugs_plugins` is in `ash_plugin_modules`; an `ash scan` that does not list it is unchanged. Once listed it runs by default and `scanners.spotbugs.enabled: false` turns it off.

### License posture

SpotBugs is LGPL-2.1 and Find Security Bugs is LGPL-3.0. Neither is bundled, vendored or added to the container image. `ash dependencies install --tool spotbugs` downloads the pinned releases (SHA256-verified) when the user runs it, and ASH starts them as a separate process. This is the user-installed shape the license check requires; it is deliberate and unchanged. Java is the user's.

### Facets declared

- Mapping register (`facets`): rule_id, severity, file_path, line_range, message and extras MAPPED; taxonomy_cwe (`rules[].relationships`), remediation_text (`rules[].fullDescription`), references (`rules[].helpUri`) and tags (the category on the rule) DROPPED; the rest N/A with reasons. Every native field is from the captured SARIF. resource_id is N/A: a Java symbol is not a deployable resource.
- Operational register (`operational_facets`): no network (bundled), SARIF output, SAST over source code (bytecode), user-installed CLI runtime needing `java`, native severity (HIGH, MEDIUM, LOW, INFO), `@SuppressFBWarnings` in the bytecode as the one tool-side silencing layer, positional identity, success exit codes 0 to 3, community opt-in tier, license "not read" (no pinned upstream LICENSE read was made).

### Findings fixed

- MUST/HIGH, test cannot pass: `TestExitStatus.test_an_error_flag_or_any_other_code_fails_even_with_a_report_on_disk` (5 cases). The base `scan()` refuses a code outside `success_exit_codes` before the results file is read, so the scanner's own `_read_results_file` check was unreachable and the message it promised never appeared. The dead override is removed and the test asserts the base refusal.
- Also failing on main's shape: `test_a_tree_without_compiled_code_never_reaches_the_tool` expected the no-bytecode skip not to be an error, but the skip was written to the error stream. It is now logged without joining the errors.
- HIGH, checklist row 24: real captured fixtures and `captured/README.md` under `tests/test_data/scanners/spotbugs/` (SpotBugs 4.10.5 and Find Security Bugs 1.14.0 over dom4j 2.2.0, a positive run of 300 results and a negative run), with tests that read the severity mapping, the `security_only` filter and the exit-2 clean run over them. Pinned digests were checked before the run.
- HIGH, checklist row 25: `tests/unit/plugin_modules/test_spotbugs_sandbox_requirements.py` pins the strict default sandbox declaration.
- Docs claimed `JAVA_HOME` is not passed under `--sandbox`; the policy measured the other way (it is passed, `JAVA_TOOL_OPTIONS`, `_JAVA_OPTIONS` and `fb_maxheap` are not). Docs and the docstring are corrected and the test pins it.

### Central registration owed (not made here)

- `automated_security_helper/utils/scanner_names.py`: add `"spotbugs": "SAST",` to `SCANNER_TOOL_TYPES`.
- `tests/unit/plugin_modules/test_scanner_facets_corpus_consistency.py`: add `"spotbugs": CorpusSpec("spotbugs", sarif=("captured/*.sarif",)),` to the corpus table.
- `tests/unit/walked_package.py`: add `"plugin_modules/ash_spotbugs_plugins",` to `PACKAGE_DIRS` (a whole-tree collect fails without it).
- The universe-count assertions (`== 22`) in `test_scanner_facets_registry_totality.py`, `test_scanner_facets_corpus_consistency.py` and `test_scanner_operational_facets_consistency.py` move with every scanner added.
- Generated docs rows, the plugin tables and the schema snapshots are an integration pass.

### Desk counts

On dev-dsk-cbc4ff77, from a repository extract, `uv sync --frozen --all-extras --group dev`, `env -i`, `-n 4`:

- This module's tests plus the sandbox test: 75 passed, 0 failed.
- Facets families (registry totality, resource-id conformance, corpus consistency, operational consistency, both vocabulary tests) with the central edits above applied on the desk: 20 failed, 588 passed. The same 20 fail on unmodified origin/main (corpus cells of other scanners), so none is this scanner's. As committed, without the central edits, 5 more fail, each naming one of the central edits above (two count tests, the tool-type table, the corpus table, and the corpus row for spotbugs).
- Whole-tree `--collect-only`: 72,834 collected, 1 error, the missing `PACKAGE_DIRS` entry above.
