## feat(plugins): Polaris alpha scanner plugin (Kubernetes manifest checks)

Branch `scanner/polaris`, based on main e0aac6c3aff. Alpha, community opt-in: the module loads only when listed in `ash_plugin_modules`; a scan that does not list it is unchanged.

### What it scans

`polaris audit --audit-path` (Polaris v10.2.6, Apache-2.0) over the scan target's Kubernetes YAML, with the built-in checks only. No cluster, no network. ASH passes `--disallow-exemptions` (the tree cannot hide findings with exempt annotations) and no `--config` (the tree cannot add checks). Polaris's JSON has no file or line, so the converter finds each object's file by reading the tree's YAML for `kind`, `metadata.name` and `metadata.namespace`, and reports the line of `metadata.name`. Severity: danger is HIGH/error, warning is MEDIUM/warning, an undocumented value is HIGH. Exit 0 and 3 are completed runs; anything else fails the scan.

### Facets declared

- Facets register: rule_id, severity, file_path, line_range, message, tags, extras MAPPED. resource_id and resource_type DROPPED (the object kind, name and namespace are in Polaris's output and are folded into the message; the adapter never writes `ash_resource_id`). column, package_*, CVE, CWE, fingerprints, fix_available, remediation_text, snippet, references N/A with reasons.
- Operational register: network none (bundled), output tool JSON, targets iac_kubernetes, runtime user-installed CLI with a module-local pinned installer, severity native, one tool-side silencing layer (exempt annotations, not honored), positional-only identity, exit codes (0, 3), tier community opt-in, license Apache-2.0 with the cited LICENSE read.

### Fixes from the build review

- MUST: install-command construction raised because the shared pinned-tool table has no Polaris entry. The pin is now module-local (`polaris_install.py`): version, per-platform asset, archive SHA256 from the release `checksums.txt` (cross-checked against GitHub's asset digests and a downloaded linux/amd64 archive) and the SHA256 of the executable inside each archive. The command table never raises, and a half-applied bump is refused by name.
- MUST: `test_positive_report_is_located_and_rated` expected line 5; `metadata.name` of its manifest is line 4.
- MUST: `test_a_file_under_ashs_output_directory_is_not_a_location` built a scanner whose output directory was outside the tree, so the tree's `.ash/ash_output` was not ASH's output; the scanner now uses it.
- HIGH: the timeout test asserted `timed out after 5`; the shared flow writes `PolarisScanner timed out after '5' s and was killed, so it produced no results file`.
- HIGH (row 24): captured fixtures in `tests/test_data/scanners/polaris/captured/` from a real v10.2.6 run (positive and negative native JSON, the manifests, the converter's SARIF, a README with the commands); severity mapping is pinned over the capture.
- HIGH (row 25): sandbox-requirements test (strict default, no extra variable reaches the sandbox).
- The install test also asserted `"polaris" in commands[0]` on a `CustomCommand`; it now reads the argv.

License posture: Apache-2.0, no gate; the binary is downloaded at install time and never vendored.

Measured while writing it: Polaris follows a file symlink that leaves the tree (it reported an object defined only outside). The converter reads only regular files inside the tree, so such an object is dropped and counted in a warning, never reported.

### Central registration owed (not made here)

These shared files need one edit each; an integration lane serializes them.

1. `automated_security_helper/utils/scanner_names.py`: add `"polaris": "IAC",` to `SCANNER_TOOL_TYPES`.
2. `tests/unit/plugin_modules/test_scanner_facets_corpus_consistency.py`: add `"polaris": CorpusSpec("polaris", sarif=("captured/*.sarif",)),` to `CORPORA`, and bump the scanner count 22 to 23.
3. `tests/unit/plugin_modules/test_scanner_facets_resource_id_conformance.py`: add `"PolarisScanner": ("polaris/captured/positive.json", "Name", "web"),` to `_DROPPED_FIXTURES`.
4. `tests/unit/plugin_modules/test_scanner_operational_facets_consistency.py`: add `"polaris": ("polaris/captured/positive.json", opsf.OutputFormat.TOOL_JSON),` to `_NATIVE_FIXTURES`, and bump the count 22 to 23.
5. `tests/unit/plugin_modules/test_scanner_facets_registry_totality.py`: bump the count 22 to 23.
6. `tests/unit/walked_package.py`: add `"plugin_modules/ash_polaris_plugins",` to `PACKAGE_DIRS` (without it, whole-tree collection fails).
7. `tests/unit/plugin_modules/test_walking_scanners_skip_links_leaving_the_tree.py`: `test_every_registered_scanner_has_a_link_handling` needs a row or exemption for polaris (Polaris walks the directory itself and follows file links; see the measurement above).
8. Optional: `core/scanner_inventory.py` module list, as for the other community modules.

### Desk validation (dev-dsk-cbc4ff77, tree shipped as a repository, `uv sync --frozen --all-extras --group dev`, `env -i`, `-n 4`, Python 3.12.15)

With the central edits above applied on the desk extract only (not committed):

- Polaris tests selected by name across `tests/unit/plugin_modules`: 98 passed, 0 failed.
- Facets families plus the Polaris module tests (611 tests): 591 passed, 20 failed. The 20 are `test_declared_facets_agree_with_the_observed_corpus[...]` rows of other scanners; the same 20 fail on main with the Polaris module removed (455 passed, 20 failed in the four families alone), so they are not caused by this change.
- Whole `tests/unit/plugin_modules`: 8850 passed, 21 failed, 394 skipped. The 21 are those 20 and `test_every_registered_scanner_has_a_link_handling` (central item 7).
- Whole-tree `pytest --collect-only -q`: 74383 tests collected, no error (with central item 6; without it, one collection error).
