## Conftest alpha scanner (`ash_conftest_plugins`)

### What it scans

`conftest test` over the configuration files of the scan target (YAML, JSON, TOML, HCL, Terraform, Dockerfile, INI, XML and the other formats Conftest parses), against Rego policies the operator supplies. Conftest ships no rules, so the scanner does nothing until a policy directory (default `policy/`, option `policy_dir`) holds a `.rego` file; with none it reports SKIPPED, not PASSED. Findings are the policy's `deny` (HIGH) and `warn` (MEDIUM) results.

### Tier

Alpha, opt-in community plugin: loaded only when `ash_conftest_plugins` is listed in `ash_plugin_modules`. Strict sandbox, no network.

### Facets declared

Both registers are declared on the class (`facets`, `operational_facets`).

- Mapped: rule id, severity, file path, message, tags, extras.
- N/A with reason: line range and column (the real report carries no region), resource id and resource type (a policy result names a file, not a deployable resource), package fields, CVE and CWE, fingerprints, fix, remediation, snippet, references.
- Operational: user-installed CLI, no network, SARIF on stdout, severity derived from the policy level, one tool-side layer (Rego `exception` rules), positional-only identity, operator-path rules, exit codes `{0}` under `--no-fail`, community opt-in. Upstream license is declared `not read`: no pinned LICENSE read exists in this lane.

### Fixed in this branch

- MUST (integration dependency): the scanner constructor called `pinned_tool_install_commands("conftest")`, which raises because `utils/tool_downloads.py` has no conftest entry, so the scanner could not be constructed. It now builds with no install command and the dependency hint no longer names an install ASH cannot do. The README and docs page no longer claim an installer, a container-image copy or a bundled license file.
- HIGH, rows 18, 21, 24: real captured fixtures. `tests/test_data/scanners/conftest/captured/` holds `positive.sarif`, `negative.sarif` and a README, captured from a real Conftest 0.62.0 run (OPA 1.6.0, linux/x86_64). The tests now serve them. The capture showed the earlier hand-written report was wrong: Conftest SARIF results have no region, so there is no line to report. The tests, the facets (line and column are N/A) and the docs suppression example are corrected.
- HIGH, row 25: `tests/unit/plugin_modules/test_conftest_sandbox_requirements.py` pins the strict default over `build_scanner_policy`.
- Row 11: install behavior is tested (constructs with no pin; uses a pin when one exists; the dependency hint names no ASH install).

### License posture

ASH does not download, bundle or redistribute Conftest, so nothing is vendored and no license file ships.

### Central edits still owed (not made here; an integration lane serializes them)

1. `automated_security_helper/utils/tool_downloads.py`: add a `conftest` pin (`TOOL_VERSIONS`, asset table with digests; v0.62.0 is the release the fixtures were captured with). With it, `pinned_tool_install_commands("conftest")` stops raising and the scanner installs with `ash dependencies install --tool conftest`; the operational row's runtime and platforms cells then change to a pinned binary.
2. `automated_security_helper/core/scanner_inventory.py`: add `automated_security_helper.plugin_modules.ash_conftest_plugins` to the community module list.
3. `automated_security_helper/utils/scanner_names.py`: add `"conftest": "IAC"` to `SCANNER_TOOL_TYPES`.
4. `tests/unit/walked_package.py`: add `plugin_modules/ash_conftest_plugins` to `PACKAGE_DIRS` (without it whole-tree collection errors).
5. The registry tests count scanners and key corpora: `test_scanner_facets_corpus_consistency.py` (22 to 23 and a `CORPORA` row pointing at `tests/test_data/scanners/conftest`), `test_scanner_facets_registry_totality.py` and `test_scanner_operational_facets_consistency.py` (the "twenty two" universe).

Until 2 to 5 land, adding any new plugin package fails those tests by design.

### Desk validation

Desk dev-dsk-d14420e2, shipped as a repository, `uv sync --frozen --all-extras --group dev`, `env -i`, `-n 4`, lane under `/run/user/23503848/`:

- Conftest module tests plus the sandbox test: 49 passed, 0 failed.
- Facets families (corpus consistency, registry totality, resource-id conformance, operational consistency): the conftest declarations pass the totality and conformance rows. The families have 20 failures with the module removed (all in the corpus-consistency `declared_facets_agree` rows for every existing scanner, on this desk), and 5 more with it: the conftest corpus row, the three 22-scanner counts and the tool-type story, all items 3 and 5 above.
- Whole-tree collect smoke: 74312 of 74357 collected, 1 collection error, the `PACKAGE_DIRS` check (item 4).
- Extract removed and absence read back.
