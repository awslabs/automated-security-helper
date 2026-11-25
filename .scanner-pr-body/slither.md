## Add the Slither alpha scanner plugin module

Adds `automated_security_helper.plugin_modules.ash_slither_plugins`, an opt-in alpha scanner for Solidity smart contracts using [Slither](https://github.com/crytic/slither) (crytic, AGPL-3.0).

### What it scans

`slither` over the scan root, once for the source tree and once for the converted tree. Slither compiles through the project's own framework (Hardhat, Foundry) or the `.sol` files directly in a bare directory. A tree with no `.sol` file is SKIPPED and Slither is not started. The plugin reads Slither's `--json` output and builds the SARIF itself, because Slither's own SARIF writer marks every result `warning`.

Argv: `slither --json=<report> --config-file=<empty file> --triage-database=<missing file> --fail-none --exclude-dependencies -- <path>`, working directory the source directory. `success_exit_codes` is `{0}` (with `--fail-none` a run that found things exits 0; the default exits 255).

### Tier

Alpha, opt-in: the module is loaded only when it is listed in `ash_plugin_modules`. `tier = community_optin` in the operational register.

### Facets declared

Both register rows are declared on `SlitherScanner`.

- `facets` (finding facets): rule_id, severity, file_path, line_range, message, fingerprints, tags and extras are MAPPED. column and references are DROPPED with reasons (the columns are not copied; the documentation URL goes to the rule `helpUri`, which the flat row does not read). resource_id and resource_type are N/A (a finding names a contract element in source, not a deployable resource). package fields, CVE, CWE, fix_available, remediation_text and snippet are N/A with reasons.
- `operational_facets`: no network fetch, BUNDLED offline strategy, strict sandbox default, native output TOOL_JSON, target SOURCE_CODE (SAST), user-installed CLI, severity NATIVE, success exit codes (0,), provenance COMMUNITY_OPTIN / USER_INSTALLED. Silencing records two repository-writable layers: inline `slither-disable` comments (honored, measured) and `slither.config.json` / `slither.db.json` (not honored, see below). Upstream license is `not read`: the register accepts only a read of a pinned upstream LICENSE, and none was read here.

### Findings fixed (the scanner-plugin review's row for slither: 1 MUST, 2 HIGH)

- MUST, tree configuration: Slither loads `slither.config.json` from its working directory, and also `slither.db.json` (triage database). Measured on slither 0.11.6 with a Solidity file carrying a reentrancy bug, an unprotected `selfdestruct` and a low-level call: a `detectors_to_exclude` config hid 3 of 4 findings and a triage database hid all 4. The scan now passes `--config-file` (an empty `{}` file) and `--triage-database` (a path that does not exist), both in ASH's own results directory; all 4 findings return. Tests: `TestTreeConfiguration`.
- HIGH, captured fixtures (checklist rows 18 and 24): `tests/test_data/scanners/slither/captured/` now holds `positive.json`, `clean.json` and the stderr summaries from a real run of slither 0.11.6 with solc 0.8.28, a README with the argv, and `positive.sarif` made by `convert_slither_json` from the captured JSON. `TestCaptured` runs the converter over the real document and checks severity, level, location (a multi-line region keeps both ends).
- HIGH, sandbox policy test (row 25): `tests/unit/plugin_modules/test_slither_sandbox_requirements.py`, built with `build_scanner_policy`, same shape as the betterleaks test.
- Found while capturing, not in the RESULTS row: Slither's JSON for a clean analysis and for a run that analyzed nothing is the same bytes (`{"success": true, "error": null, "results": {}}`, exit 0). A directory with no supported project at its root and no `.sol` file directly in it (sources in `contracts/`, target `.`) produced 0 contracts and would have read as clean. The scan now reads the summary line in Slither's stderr log and fails with an error when it reports 0 contracts or is missing. Tests: `TestAnalyzedNothing`, including the two captured documents being identical.
- Also from the checklist: severity mapping is tested over the captured report, not only hand-written documents (row 18).

### License posture

Slither is AGPL-3.0, so the no-install design is deliberate and kept: the plugin declares no install command and no download, `ash dependencies install` does nothing for it, and a missing `slither` reports the scanner MISSING with the install line (`uv tool install slither-analyzer`). `TestLicenseGate` pins this. Nothing from Slither is vendored.

### Central registrations owed (outside this module; the integration lane serializes them)

This branch edits nothing outside the module, its tests, its docs page and its captured fixtures. With the module present, these central items need one edit each:

- `automated_security_helper/utils/scanner_names.py`: add `"slither": "SAST",` to `SCANNER_TOOL_TYPES`.
- `automated_security_helper/core/scanner_inventory.py` (line 75 list): add `"automated_security_helper.plugin_modules.ash_slither_plugins",`.
- `tests/unit/walked_package.py` (`PACKAGE_DIRS`): add `"plugin_modules/ash_slither_plugins",`. Without it, whole-tree collection errors with `not named in PACKAGE_DIRS`.
- `tests/unit/plugin_modules/test_scanner_facets_corpus_consistency.py`: add `"slither": CorpusSpec("slither", sarif=("captured/*.sarif",)),` to the corpus table, and change the scanner count from 22 to 23 here and in `test_scanner_facets_registry_totality.py` and `test_scanner_operational_facets_consistency.py`.
- The `.ash/.ash_community_plugins.yaml` list and the CI workflow module lists are not edited: the Dockerfile and container validation lists omit Slither on purpose (AGPL, not in the image).

### Desk counts (dev-dsk-cbc4ff77, CPython 3.12.15, `uv sync --frozen --all-extras --group dev`, `env -i`, lane under `/run/user/<uid>`, basetemp in the lane, `-n 4`)

- Module tests (`tests/unit/plugin_modules/ash_slither_plugins`, `test_slither_sandbox_requirements.py`): 58 passed, 0 failed.
- Facets families (registry totality, corpus consistency, resource-id conformance, operational consistency, the two vocabulary files) plus the module tests, with the central edits above applied in the desk scratch copy only: 571 passed, 20 failed, none of the 20 involve slither. The 20 are the corpus-consistency rows of existing scanners (betterleaks, bandit, checkov and others; for example betterleaks reads its `tags` column empty). They were not run on a bare `origin/main` checkout, so whether they are red there is unmeasured here; the first run of this extract without the central edits read 25 failed, which is these 20 plus the 5 slither rows listed next.
- Without the central edits: the slither rows that fail are exactly the five that need them (corpus table row, tool-type story, the two 22-scanner count assertions, the corpus-table agreement).
- Whole-tree collect smoke: 74,321 of 74,366 collected, 1 error (the `PACKAGE_DIRS` item above).
- The desk extract and the capture lane were removed and their absence read back.
