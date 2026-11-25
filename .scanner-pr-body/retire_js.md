# feat(plugins): retire_js alpha scanner plugin module

Branch `scanner/retire_js`, based on main at e0aac6c3aff. Not opened as a PR: the combined scanner PR opens after the remaining mainline changes land.

## What the tool scans

[retire.js](https://github.com/RetireJS/retire.js) (Apache-2.0) finds known-vulnerable JavaScript libraries by file name, file content and file hash, and compares each version with its vulnerability repository. It finds a vulnerable jQuery copied into `static/` that no lockfile names, the gap `npm-audit` and `grype` leave. It does not read `package.json` or a lockfile: a real retire 6.1.1 run over a tree holding only a `package.json` that names lodash 4.17.4 reports nothing. The module documents that and no longer claims manifest scanning.

ASH runs `retire --outputformat=json --outputpath=<file> --exitwith=13 --nocache --ignorefile=<file holding []> [--ignore=<ASH output dirs>] --path=<target>` and converts the JSON report to SARIF. The pin is retire 6.1.1, installed with `npm install -g` (`ash dependencies install`).

## Tier

Alpha, opt-in community module: `automated_security_helper.plugin_modules.ash_retire_js_plugins` in `ash_plugin_modules`. A scan that does not list it is unchanged. It is skipped under `--offline` (`SKIP_OFFLINE`): retire.js fetches its vulnerability repository on every run. Sandbox: `SandboxRequirements(network=True)` and nothing else (a policy test builds it and compares with the strict default).

## Facets declared

Both register rows are declared on the class: `facets` (what the native output maps) and `operational_facets` (how the scanner runs).

- Mapped: rule id (CVE, else GitHub advisory id, else a `RETIREJS-...` id), severity, file path, line range (the adapter's constant `startLine 1`, declared as such), message, package name, package version, CVE (through the rule id), CWE (written into the result tags), tags, extras.
- Resource identity: `resource_id` and `resource_type` are N/A with reasons. A finding names a library file and version, not a deployable resource. Library identity is carried by the package name and version cells.
- Dropped: `fix_available` (`vulnerabilities[].below` is quoted in the message only) and `references` (`vulnerabilities[].info` stays in the property bag and the rule `helpUri`).
- N/A with reasons: column, package path, fingerprints, remediation text, snippet.
- Operational: content fetch of the vulnerability database, offline outcome `not_run`, TOOL_JSON output, SCA over package sources, user-installed CLI with Node as a prerequisite, native severity, repository ignore files declared not honored, positional-only identity, exit codes (0, 13), community opt-in, Apache-2.0 with a source citation (the `retire@6.1.1` package.json license field and LICENSE.md, read 2026-11-25).

## Fixed from the RESULTS row

- MUST: the documented and test-encoded capability "reads dependencies from package.json" was false at the pinned tool. Fixed in the module docstring, class docstring, plugin README, docs page and tests. The hand-written positive report no longer has a `package.json` entry with `detection: dependencies`; a test asserts the real capture of a package.json-only tree is empty and that the documentation says retire.js does not read manifests.
- HIGH, row 18 and row 24 (no captured fixtures): `tests/test_data/scanners/retire_js/captured/` now holds `positive.json` and `negative.json` from a real retire 6.1.1 run, a README with the argv and the edits (path prefix rewritten, JSON re-indented by the repository formatter), and `retire_js-6.1.1.sarif`, the converter's output, with a test that regenerates it and fails on any difference. Severity mapping is tested row by row and over the real capture (six medium, one low; the low one has no CVE or GitHub id and gets `RETIREJS-jquery-issue-162`).
- HIGH, row 25 (no sandbox-requirements test): `test_retire_js_sandbox_requirements.py` builds the policy with `build_scanner_policy`: network granted online and never offline, read-only, cache and writable paths equal to the default's, and no tree or host variable reaches the tool.
- Test that could not pass: the timeout test matched `timed out after 5`; the real message is `timed out after '5' s`. Fixed.
- Found while capturing: retire.js writes absolute `file` paths, resolved when the source directory sits behind a symlink. `_relative_uri` now tries both the absolute and the resolved root, with a test over a symlinked source.
- Added (needed by the facets cells): package name and version are written through `identity_properties`, and CWE ids ride in the result tags where the flat view reads them. Package-scoped suppressions now match (`package_name: jquery`); the docs page says so.

## License posture

No license gate: retire.js is Apache-2.0 and ASH does not redistribute it. The docs page states that. The README says nothing about acceptance, accounts or tokens because none is needed.

## Central registration owed (not edited here)

Discovery of a community module needs edits to shared files, which an integration lane serializes. The exact edits:

1. `automated_security_helper/core/scanner_inventory.py`, in `_VENDORED_SCANNER_PLUGIN_PACKAGES`, add `"automated_security_helper.plugin_modules.ash_retire_js_plugins",` (between the guarddog/hadolint entries and the snyk entry, sorted).
2. `automated_security_helper/utils/scanner_names.py`, in `SCANNER_TOOL_TYPES`, add `"retire_js": "SCA",`.
3. `tests/unit/plugin_modules/test_scanner_facets_corpus_consistency.py`: add `"retire_js": CorpusSpec("retire_js", sarif=("captured/*.sarif",)),` to `CORPORA`, and change the scanner count `22` to `23` (one assertion).
4. `tests/unit/plugin_modules/test_scanner_facets_registry_totality.py` and `tests/unit/plugin_modules/test_scanner_operational_facets_consistency.py`: count `22` to `23`; in the operational test, the not-run list becomes `["npm-audit", "retire_js", "snyk-code"]`.

5. `tests/unit/walked_package.py`, in `PACKAGE_DIRS`, add `"plugin_modules/ash_retire_js_plugins",` (without it `tests/unit/test_walked_package.py` fails at collection, and the whole-tree collect ends with that one error).
6. The remaining registry-completeness tests that name every in-tree community scanner and go red until it is listed. Each failure names `retire_js` as the missing member; measured on the desk copy with 1 to 5 applied:
   - `tests/unit/plugin_modules/test_walking_scanners_skip_links_leaving_the_tree.py::test_every_registered_scanner_has_a_link_handling` (a row for `retire_js` in the link-handling tables; retire.js walks the whole target itself, so it is the "handed the tree" kind).
   - `tests/unit/config/test_off_host_plugins_are_operator_only.py::test_every_shipped_plugin_is_classified` (classify `("scanners", "retire_js")` as LOCAL: it grants no off-host reach).
   - `tests/unit/docs/test_page_claims.py`: `test_the_coverage_tables_name_every_shipped_scanner_by_where_it_comes_from`, `test_the_homepage_says_asha_ships_six_community_scanners_and_links_each` (six becomes seven) and `test_the_plugins_overview_names_every_community_scanner_and_no_other` (docs index, coverage and plugins-overview rows).
   - `tests/unit/utils/test_third_party_licenses.py::TestThePythonTools::test_every_ash_dependencies_install_takes_the_pins` (the inventory list, item 1).

Without these, the registry-wide tests that enumerate `plugin_modules` packages go red on the count and on the missing table rows. Applied on a desk copy only (items 1 to 5), they turn every retire_js row green (below). This module needs no scanner options, so nothing in the `ash_config.py` policy lists; CHANGELOG and generated references belong to the integration lane.

## Desk validation

Desk dev-dsk-cbc4ff77, lane under `/run/user/23503848/`, shipped as a repository (`git archive`, then `git init`), `uv sync --frozen --all-extras --group dev`, `env -i` with HOME, USER, PATH, CI=1 and TMPDIR, `-n 4`, `--basetemp` in the lane, Python 3.12.15.

- The retire_js module tests: 0 failed.
- Facets registry, corpus, resource-id conformance and operational consistency families plus the community import-order test, with the central edits above applied on the desk copy only: 544 passed, 1 skipped, 20 failed. The 20 failures are `test_declared_facets_agree_with_the_observed_corpus[<scanner>]` for the 20 scanners other than retire_js, and they fail identically on main without this module (measured: 20 failed, 455 passed over the four families with the module removed). 0 failed in the retire_js rows.
- Whole-tree collect smoke (`pytest tests --collect-only -q`): 74330 of 74375 collected (45 deselected) with 1 collection error, `tests/unit/test_walked_package.py`, which is registration item 5; with it applied the same tests pass (see item 6's run: 923 passed, 798 skipped, and the 6 registry-completeness reds listed there, all naming `retire_js`).
- ruff format --check and ruff check: green (the repository hooks ran on both commits). Marker scan: zero. Whole-range audit: one noreply identity line.
