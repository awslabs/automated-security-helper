## gosec scanner plugin (alpha, opt-in)

Adds `gosec` as a community scanner module, `ash_gosec_plugins`. It runs gosec over Go
modules and reads the SARIF gosec writes itself.

### What it scans

`gosec -fmt=sarif -out=<report> -nosec=true -- ./...` from the source directory, over a
project with a `go.mod`. `#nosec` comments are ignored so every finding reaches ASH,
where suppressions are reported and counted. No `-conf`, no `-no-fail`, no AI flags.
gosec exits 0 for a clean scan and 1 for findings or a processing error; exit 1 with an
empty report is refused as a failed run, not passed as clean. Test files are scanned
only with `options.include_tests`.

### Tier

Alpha, opt-in: listing `automated_security_helper.plugin_modules.ash_gosec_plugins` in
`ash_plugin_modules` turns it on. Not in the builtin config. `python_only` is false (a
native binary plus the Go toolchain, which ASH does not install). Strict default
sandbox: no network, baseline environment.

### Facets declared

- Facets register row: rule_id, severity, file_path, line_range, column, message,
  snippet and extras mapped; resource_id and resource_type n/a (source findings name a
  file location, not a deployable resource); package_* and taxonomy_cve n/a;
  taxonomy_cwe, tags dropped (the CWE is in rule relationships and the tags sit on the
  rule, not the result); fingerprints n/a (none in gosec's SARIF); fix_available,
  remediation_text, references n/a.
- Operational register row: no fetch, bundled offline, SARIF output, source-code
  target (SAST), pinned binary (`go` an external program), severity native, silencing
  by `#nosec` not honored, identity positional only, no custom rules, exit codes
  (0, 1), community opt-in, Apache-2.0, prerequisite a Go module.

### Fixed from the build review

| Finding | Fix |
|---|---|
| MUST: install validator raised (`pinned_tool_install_commands("gosec")` for a tool the shared pin table does not know), so the scanner could not be constructed | The install table is filled only when the pin is registered; otherwise it stays empty, construction works, and the missing-tool warning says no pin exists. Tested both ways, plus the real pin once registered. |
| MUST: committed `scan()` tests failed at the validator | Same root cause; the whole behavior file now passes. |
| HIGH rows 18 and 24: severity not tested over a real captured report; no captured fixtures or README | `tests/test_data/scanners/gosec/captured/` holds real gosec v2.30.0 reports for a positive and a negative input, with a README giving argv, version, inputs and the facts the adapter relies on. Severity rows are tested over the capture (G402 HIGH, G304 MEDIUM, G104 LOW), plus an unreadable-tag case. |
| HIGH row 25: no sandbox requirements test | `tests/unit/plugin_modules/test_gosec_sandbox_requirements.py`. |
| HIGH row 22: timeout assertions missing | The scan timeout reaches the subprocess (`0 < timeout <= scan_timeout`), and a timeout fails with a message naming it. |

A capture finding worth knowing: gosec omits `ruleIndex` on results of the first rule,
so the adapter keys severity on `ruleId`, which it already did.

### License posture

gosec is Apache-2.0 (checked from the `LICENSE.txt` in the v2.30.0 release archive).
There is no license or service gate and nothing is vendored. The design keeps no
install gate because none is needed.

### Central registration still owed (integration change)

This branch edits nothing outside the module, its tests and its facets declarations.
`.scanner-pr-body/gosec-central.patch` holds the shared-file edits, verified on the desk
as described below (apply with `git apply`):

1. `utils/tool_downloads.py`: the gosec pin (v2.30.0, the six archive names, archive
   digests from the release's `gosec_2.30.0_checksums.txt`, executable digests, release
   base URL, asset table). All six archive and executable digests were re-derived on the
   desk by downloading each asset and hashing it and the executable inside it.
2. `utils/scanner_names.py`: `"gosec": "SAST"`.
3. `core/scanner_inventory.py`: the module in `_VENDORED_SCANNER_PLUGIN_PACKAGES`.
4. `tests/unit/walked_package.py`: `plugin_modules/ash_gosec_plugins` in `PACKAGE_DIRS`.
5. The register tests: the scanner count 22 to 23 in the totality, operational
   consistency and corpus consistency files, a `gosec` row in
   `_NATIVE_FIXTURES`, and a `gosec` row in `CORPORA`.
6. Not in the patch, the usual betterleaks-shaped registrations: the third-party
   license entry for gosec in `tool_downloads.THIRD_PARTY_LICENSES` (the LICENSE.txt
   in the archive has sha256 `2be0a81f30d2b73cb3b5182b969175245042158735fcc8af133929212c772e78`),
   `docs/content/docs/plugins/community/index.md`, `docs/content/reference/scanners.md`,
   the CHANGELOG, `.ash/.ash_community_plugins.yaml`, the Dockerfile and CI legs.

Until item 1 lands, `ash dependencies install --tool gosec` offers nothing and the
missing-tool warning says to install gosec by hand; the facets rows that derive platforms
from the pin table stay red for gosec.

### Desk validation

dev-dsk-cbc4ff77, lane under `/run/user/23503848/`, shipped as a repository,
`uv sync --frozen --all-extras --group dev`, Python 3.12.13, `env -i`, `-n 4`,
`--basetemp` in the lane.

- gosec test files (behavior and sandbox): 54 passed, 0 failed.
- Every gosec row across `tests/unit/plugin_modules` (`-k gosec`: behavior, sandbox,
  registry totality, operational consistency, resource-id conformance, corpus
  consistency, with the central patch applied in the extract): 75 passed, 0 failed.
- Facets and operational vocabulary and totality families together: 568 passed, 20
  failed. The 20 are `test_declared_facets_agree_with_the_observed_corpus` rows for
  other scanners; the same 20 fail on unmodified main (measured on a pristine export of
  origin/main).
- Whole-tree `pytest --collect-only`: 74226 collected; 3 collection errors, two caused
  by the desk extract excluding `.ash/` and one by item 4 above, which the patch fixes.
- ruff format --check and ruff check: green (ruff 0.17.6, above the repo's pin
  floor); the repo's pre-commit hooks passed at commit time.
- Marker scan over the changed files: zero hits, with a planted control caught.
- Identity audit over `origin/main..HEAD`: one noreply identity, author and committer.
- Pin verification: each of the six assets downloaded, archive sha256 and executable
  sha256 equal to the pinned values.
- The extract and the capture lane were removed and their absence read back.

Base: origin/main at e0aac6c3aff7 (commissioned tip d81156b9e0a4, merge-base
dc119ea09d1d).
