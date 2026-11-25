feat(plugins): njsscan alpha scanner plugin

## What it scans

njsscan (https://github.com/ajinabraham/njsscan) is a static security scanner for Node.js applications. It runs a curated rule pack over JavaScript files and template files (handlebars, pug, ejs, vue and others) and reports each match with an OWASP and CWE mapping. ASH runs it as a separate process, installed through `uv tool` from PyPI (`njsscan==1.0.2`), once per target:

```text
njsscan --sarif --output=<results>/<target_type>/njsscan.sarif --config=<empty config> -- <path>
```

## Tier

Alpha, opt-in. The plugin module is loaded only when `automated_security_helper.plugin_modules.ash_njsscan_plugins` is listed in `ash_plugin_modules`. The builtin default config does not declare it.

## Facets declared

Both register rows are class attributes of `NjsscanScanner`, written from a real njsscan 1.0.2 run (fixtures under `tests/test_data/scanners/njsscan/captured`).

- `facets` (base/scanner_facets.py): rule_id, severity, file_path, line_range, column, message, snippet, taxonomy_cwe and extras are MAPPED; references (the rule `helpUri`) and tags (rule-level) are DROPPED with the reason; resource_id, resource_type, the package facets, taxonomy_cve, fingerprints, fix_available and remediation_text are N/A with a reason each. resource_id is N/A: findings name a file location, not a deployable resource.
- `operational_facets` (base/scanner_operational_facets.py): network none and offline unchanged (BUNDLED, with the semgrep metrics setting recorded as unconfirmed), SARIF output, SAST over source code, uv_python runtime run once per target, severity NATIVE, three silencing layers (inline `njsscan-ignore` comments honored, `.njsscan` in the tree not honored, the tool's built-in ignore paths honored), positional-only identity, exit codes 0 and 1, community opt-in tier from PyPI via uv, LGPL-3.0-or-later cited to the 1.0.2 wheel metadata, no prerequisites.

## Fixed in this PR

The RESULTS row had 0 MUST and 2 HIGH, plus the unmet checklist rows 18, 21, 24 and 25.

- HIGH, no captured fixture (checklist rows 18, 21, 24): `tests/test_data/scanners/njsscan/captured/` holds `positive.sarif`, `negative.sarif` and `errored.sarif` written by the real tool, with a README. `TestCapturedReports` serves them through the scanner. The WARNING result in the real output has no `level` key, which is the case the scanner already treated as MEDIUM and which the hand-built fixtures did not show.
- HIGH, no sandbox requirements test (row 25): `tests/unit/plugin_modules/test_njsscan_sandbox_requirements.py` builds the policy with `build_scanner_policy`.
- Found while capturing, fixed in the module: njsscan starts `semgrep` by name, so a pre-installed copy run directly (a symlink from `uv tool install`) failed with "semgrep not found", exit 1 and `executionSuccessful: false`. `_direct_exec_env` puts the real directory of the executable first on `PATH` for a direct run; under `uv tool run` the environment is unchanged. Tested with a symlinked executable.
- The module header said `.njsscan` could set four keys; njsscan 1.0.2 also reads `severity-overrides`. The header and the docs page now say so, and say that njsscan's built-in ignore paths (`node_modules`, `fixtures`, `spec`, `example`, `.min.js` and others) stay in force.
- The docs page records that njsscan reads neither file links nor directory links (measured, with an in-tree control).

## License posture

njsscan is LGPL-3.0-or-later. It is not vendored, bundled or imported: ASH installs it with `uv tool` and runs it as a subprocess, so the wrapper is not a combined work. There is no pinned binary and no redistributed material, so there is no license gate to enforce beyond keeping it that way.

## Central registration still owed (an integration lane serializes these)

Not made here, per the build order. The exact one-line edits, each verified on a desk copy to make this module pass every shared test:

1. `automated_security_helper/core/scanner_inventory.py`, `_VENDORED_SCANNER_PLUGIN_PACKAGES`: add `"automated_security_helper.plugin_modules.ash_njsscan_plugins",`
2. `automated_security_helper/utils/scanner_names.py`, `SCANNER_TOOL_TYPES`: add `"njsscan": "SAST",`
3. `tests/unit/walked_package.py`, `PACKAGE_DIRS`: add `"plugin_modules/ash_njsscan_plugins",`. Without it, whole-tree collection stops with one error.
4. `tests/unit/plugin_modules/test_walking_scanners_skip_links_leaving_the_tree.py`: add `"njsscan": FOLLOWS_NO_LINK,` to `LINK_HANDLING` and `"njsscan": ("ash_njsscan_plugins.njsscan_scanner", "NjsscanScanner", "Njsscan"),` to `SCANNER_CLASSES`.
5. `tests/unit/plugin_modules/test_scanner_facets_corpus_consistency.py`, `CORPORA`: add `"njsscan": CorpusSpec("njsscan", sarif=("captured/*.sarif",)),`
6. The scanner-count assertions (`== 22,`) in `test_scanner_facets_corpus_consistency.py`, `test_scanner_operational_facets_consistency.py` and `test_scanner_facets_registry_totality.py` move to the new total (each scanner added by the combined PR adds one).

Until these land, the shared register tests fail on this branch alone (the totality count, the tool-type table, the corpus table); that is the expected shape for a module added without them.

## Desk validation

dev-dsk-cbc4ff77, a git repository extract, `uv sync --frozen --all-extras --group dev` on CPython 3.12.13, `env -i`, lane under `/run/user/<uid>/`, `--basetemp` in the lane, `-n 4`.

- Module families (behavior tests, captured-report tests, direct-exec env tests, sandbox test): 70 passed, 0 failed.
- With the six central edits above applied on the desk copy only: the njsscan module tests, the walking-scanner link test, the facets totality, corpus, resource-id and operational-consistency families, both vocabulary tests, the scanner-name agreement tests and the MCP list-scanners import-order test: 0 failed for njsscan in every family. The 20 `test_declared_facets_agree_with_the_observed_corpus` failures for other scanners read the same on a pristine `origin/main` extract (20 failed, 21 passed), so they are not from this module.
- Whole-tree `pytest --collect-only -q` with the PACKAGE_DIRS edit: 74374 of 74419 collected, no errors.
- One unrelated test (`test_bedrock_reporter_shows_no_text_twice`, about 52 s alone) failed once under `-n 4` load and passes alone both with and without this change.
