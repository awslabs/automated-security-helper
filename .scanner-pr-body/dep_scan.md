## dep_scan: OWASP dep-scan as an alpha scanner plugin

Adds `ash_dep_scan_plugins`, a community (alpha, opt-in) SCA scanner. Enable it by
listing `automated_security_helper.plugin_modules.ash_dep_scan_plugins` in
`ash_plugin_modules`.

### What it scans

Known-vulnerability findings for the dependencies of a source tree. OWASP dep-scan
(MIT, `owasp-depscan==6.3.2`, run as a uv tool) builds a CycloneDX BOM with cdxgen,
looks each component up in a local vulnerability database (OSV, NVD, GitHub
advisories) and writes a CycloneDX VDR. ASH converts the VDR to SARIF: one result per
advisory per affected component, rated by the highest CVSS rating.

Requires `cdxgen` (`npm install -g @cyclonedx/cdxgen`) on PATH; ASH does not install
it, and the dependency check fails with the install command when it is missing.

### Tier and behavior

- Alpha, opt-in. `offline_strategy = SKIP_OFFLINE` (the first run downloads the
  vulnerability database; dep-scan 6.3.2 has no offline flag).
- Only exit code 0 is success. A zero exit with no `*.vdr.json` is a failure, not a
  clean scan. `--fail-on-error` is passed so a failed cdxgen run cannot read as clean.
- The scanned tree's `.config/depscan.toml` is never read: `--config` points at an
  empty file kept outside the tree.
- dep-scan's stderr is kept out of the scan's errors (it can quote tree paths).

### Facets declared (`facets` and `operational_facets`)

- Mapped: rule_id, severity, file_path, message, package_name, package_version,
  taxonomy_cve (when the advisory id is a CVE), taxonomy_cwe (new: `CWE-<n>` tags),
  fingerprints (computed `depscan/v1`), fix_available (new: set when an unaffected
  version is listed), tags, extras.
- Mappable but dropped: remediation_text (`recommendation`), references
  (`source.url`, `advisories`).
- N/A: line_range, column, resource_id, resource_type, package_path, snippet.
  resource_id is N/A on purpose: a package version is not a deployable resource.
- Operational row: content fetch (vuln DB), SKIP_OFFLINE / not_run, sandbox network
  online, uv-python runtime, native severity, no tool-side silencing, computed
  stable fingerprints, exit codes {0}, community opt-in tier, MIT.

### Findings fixed (build review RESULTS row)

- HIGH, no real captured fixture (checklist rows 18 and 24): added
  `tests/test_data/scanners/dep_scan/captured/` with a real VDR from the dep-scan
  repository, a README with its provenance and the trimming, and a derived clean
  control. Every severity row is now tested over that capture.
- HIGH, no sandbox-requirements test (row 25): added `TestSandboxRequirements`, which
  builds the policy with `build_scanner_policy` and checks the network grant (online
  yes, offline no), the database cache mount, and that no tool environment passes.
- Facets: the scanner had no register declaration; both rows are added and checked
  against the capture.
- CWE and fix state were written to the property bag in forms the shared pipeline does
  not read; they are now `CWE-<n>` tags and `fix_available`.
- No MUST was recorded for this slug.

### License posture

dep-scan is MIT and is not vendored or bundled; it is a PyPI package installed with
uv at the user's request. cdxgen (Apache-2.0) is user-installed. Nothing here is
GPL, AGPL or ELv2.

### Central registration still owed (an integration lane serializes these)

The module is picked up by plugin discovery as is. These shared edits are outside the
module and were not made here:

1. `automated_security_helper/utils/scanner_names.py`: `SCANNER_TOOL_TYPES` gains
   `"dep_scan": "SCA"`.
2. `tests/unit/plugin_modules/test_scanner_facets_corpus_consistency.py`: `CORPORA`
   gains a `"dep_scan"` row. The native output is VDR JSON, so it needs a registered
   prep that runs `convert_vdr` over `tests/test_data/scanners/dep_scan/captured/
   positive.vdr.json`.
3. The hard-coded universe count of 22 in
   `test_scanner_facets_registry_totality.py`, `test_scanner_operational_facets_
   consistency.py` and `test_scanner_facets_corpus_consistency.py` goes up by one
   (more with the other new scanners).
4. `test_the_service_upload_scanner_is_the_one_that_skips_offline` pins the not_run set
   to `["npm-audit", "snyk-code"]`; `dep_scan` joins it.
5. `tests/unit/walked_package.py`: `PACKAGE_DIRS` names `plugin_modules/ash_dep_scan_plugins`
   (the whole-tree collect smoke stops on it otherwise).
6. Enabling lists that name community modules: `core/scanner_inventory.py`,
   `.ash/.ash_community_plugins.yaml`, `Dockerfile` (`ASH_COMMUNITY_PLUGIN_MODULES`,
   both stages) and the CI actions, if the scanner is to ship in the image.
7. Optional: a `CONTENT_DATABASES` entry for dep-scan's vulnerability database.

### Desk validation

dev-dsk-cbc4ff77, shipped as a repository, `uv sync --frozen --all-extras --group dev`,
`env -i`, 4 workers, CI=1.

- Module tests (`tests/unit/plugin_modules/ash_dep_scan_plugins`): 111 passed, 0 failed.
- Facets families (registry totality, resource-id conformance, corpus consistency,
  operational consistency and both vocabulary tests): 618 passed, 26 failed. On pristine
  main the same families give 494 passed, 20 failed (the corpus gate is red for all 20
  scanners already). The 6 added reds are the registration items 1 to 4 above. None is in
  the module.
- Whole-tree collect: 74,374 of 74,419 collected, 1 error (item 5).
- Extract removed from the desk and its absence read back.

