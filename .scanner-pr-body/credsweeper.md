# Add the CredSweeper alpha scanner plugin

Held PR body. The PR opens later, as part of the combined new-scanner PR, once the remaining mainline changes land.

## What it scans

CredSweeper (Samsung, MIT) finds credentials in files with regular-expression rules and scores each candidate with a small ONNX model. The plugin runs `credsweeper --path=<target> --save-json=<file> --no-stdout --no-color --no-progress --hashed --no-error` over the scan target through `uv tool run` and converts the JSON report to SARIF. The value text never enters the SARIF: the snippet is the constant `REDACTED`, and the report's own `line`, `variable` and `value` fields (hashed by `--hashed`) are not read.

Severity is rated by the model's `confidence` (strong HIGH, moderate MEDIUM, weak LOW; an unreadable confidence is HIGH). The rule's own severity and the ML probability are kept as result properties.

## Tier

Alpha, opt-in: the module `automated_security_helper.plugin_modules.ash_credsweeper_plugins` runs only when `ash_plugin_modules` lists it. A scan that does not list it is unchanged. It overlaps the builtin detect-secrets and gitleaks scanners, and a credential more than one of them finds is reported by each.

## Facets declared

Both register rows are declared on `CredSweeperScanner`.

- Facets: rule_id, severity, file_path, line_range, message, fingerprints, snippet, tags and extras are mapped; column is dropped (the report's `value_start` / `value_end` offsets are not written to the SARIF region); resource_id, resource_type, package_*, taxonomy_*, fix_available, remediation_text and references are n/a with a reason each. resource_id is n/a because a credential finding names a file location, not a deployable resource.
- Operational: BUNDLED offline strategy, no network in the sandbox, tool JSON output, secrets-contents target (tool type SECRETS), uv Python runtime run once per target, derived severity, computed stable fingerprint, no custom-rules surface, `success_exit_codes = {0}` (ASH passes `--no-error`), community opt-in tier, PyPI via uv, license MIT read from the LICENSE file in the credsweeper 1.19.7 wheel.

## MUSTs and HIGHs fixed

The build review recorded 0 MUST and 2 HIGH, with 21 of 24 applicable checklist rows met. Misses and what closed them:

- Row 18 (severity mapping tested over a report written in the test file): a real report was captured from CredSweeper 1.19.7 (`tests/test_data/scanners/credsweeper/captured/positive.json` and `negative.json`, with a README naming the argv and what the capture shows). The new tests assert the mapping over those bytes: the rule says severity high, the confidence is moderate, ASH rates MEDIUM and SARIF level warning, and no hashed field reaches the SARIF.
- Row 24 (no captured fixtures): same capture. A scan() test also serves the captured bytes through the fake subprocess for the positive and the negative.
- Row 25 (no sandbox-requirements test): `test_credsweeper_captured_and_sandbox.py` builds the policy with `build_scanner_policy` and asserts the strict default (no network, baseline read-only and cache paths, baseline environment only).
- The commissioned scan() tests pass (70 tests in the module's folder on the desk), and no install command raises.

## License posture

CredSweeper is MIT. The scanner vendors nothing: it runs the PyPI package through uv, and no source is copied into the repository. There is no no-install gate for this tool in the license check.

## Central registration still owed (an integration lane serializes these)

None of these is edited on this branch. Without them the shared registry tests fail on the 23rd scanner, so the combined PR carries them:

1. `automated_security_helper/utils/scanner_names.py`: add `"credsweeper": "SECRETS",` to `SCANNER_TOOL_TYPES`.
2. `automated_security_helper/core/scanner_inventory.py`: add `"automated_security_helper.plugin_modules.ash_credsweeper_plugins",` to `_VENDORED_SCANNER_PLUGIN_PACKAGES`.
3. `tests/unit/walked_package.py`: add `"plugin_modules/ash_credsweeper_plugins",` to `PACKAGE_DIRS`.
4. `tests/unit/plugin_modules/test_scanner_facets_corpus_consistency.py`: a `CORPORA` row `"credsweeper": CorpusSpec("credsweeper", prep="credsweeper")` and a `_prep_credsweeper` that runs `convert_credsweeper_report` over `captured/*.json` (registered in `_PREPS`).
5. The scanner-count assertions of 22 become 23 in `test_scanner_facets_registry_totality.py`, `test_scanner_facets_corpus_consistency.py` and `test_scanner_operational_facets_consistency.py`.
6. Generated docs and listings as the combined PR's generators produce them: the `docs/content/reference/scanners.md` table and section, the `docs/content/docs/plugins/community/index.md` entry, and (optional) the Dockerfile `ASH_COMMUNITY_PLUGIN_MODULES` argument and a CHANGELOG line.

## Desk counts

dev-dsk-d14420e2, repository extract, `uv sync --frozen --all-extras --group dev`, `env -i`, `-n 4`, basetemp in the lane. With the central edits 1 to 5 applied to the extract only (not committed here): the module folder 70 passed, 0 failed; the facets registry, corpus, resource-id conformance and operational consistency files plus the scanner-inventory import-order test: 547 passed, 1 skipped, 20 failed. All 20 failures are other scanners' rows in the corpus test (snyk-code, trivy, trivy-repo, betterleaks, actionlint, bandit, cdk-nag, cfn-lint, cfn-nag, checkov, detect-secrets, gitleaks, grype, npm-audit, opengrep, semgrep, syft, zizmor, ferret-scan, guarddog) and they fail the same way on main before this branch; none is a credsweeper row (19 credsweeper-keyed rows across the facets files pass). Whole-tree collect: 74374 of 74419 collected, no errors. Without the central edits the same files fail on the credsweeper rows for exactly the items in the list above. The extract was removed and its absence read back.
