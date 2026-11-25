## Add KICS as an alpha scanner plugin

### What it scans

[KICS](https://github.com/Checkmarx/kics) (Keeping Infrastructure as Code Secure) runs Rego queries over infrastructure-as-code: Terraform, CloudFormation, Kubernetes, Ansible, OpenAPI, Pulumi, Azure Resource Manager, Google Deployment Manager, Dockerfile, Docker Compose, Crossplane, Knative, Serverless Framework, Buildah, gRPC and CI/CD files. ASH runs `kics scan` once per target and reads the SARIF report plus the JSON report beside it (the JSON names each query's exact severity; the SARIF maps CRITICAL and HIGH both to `error`).

### Tier

Alpha, opt-in. The module `automated_security_helper.plugin_modules.ash_kics_plugins` is loaded only when listed in `ash_plugin_modules`; a scan that does not list it is unchanged. Strict default sandbox (no network, baseline environment). Pinned to KICS v2.1.20, the newest release that publishes binary archives.

### Facets declared

`facets` and `operational_facets` are declared on `KicsScanner` as class attributes, classified against captured reports from a real v2.1.20 run (`tests/test_data/scanners/kics/captured/`, with the argv and tool digests recorded in its README).

- Mapped: rule id (query id), severity (JSON `queries[].severity` joined by query id), file path, start line, message, extras (`message.properties`).
- Mappable but dropped: resource id (`search_key`), resource type, CWE (`queries[].cwe`), fingerprints (`similarity_id`), remediation text (`expected_value`), references (rule `helpUri`).
- Not applicable: column (KICS writes `startLine` only), package name, version and path, CVE, fix state, snippet, tags.
- Operational: pinned release binary, no network fetch, native SARIF with a JSON side report, tool-side silencing by `# kics-scan ignore` and `# kics-scan disable=<query-id>` comments in the scanned files (honored, cannot be turned off in v2.1.20; documented), `kics.config` and `.gitignore` handling fixed by ASH, success exit code `{0}` with `--ignore-on-exit=results`.

### Findings fixed (scanner-plugins build review)

- HIGH, `test_class_variables` could not fail: it compared the lowercase `OfflineStrategy` value to `"UNKNOWN"`. It now asserts `OfflineStrategy.BUNDLED` and `is not OfflineStrategy.UNKNOWN`.
- HIGH, `TestPinnedRelease` failed and the scanner was unconstructible outside the test file because `tool_downloads.py` has no `kics` rows. `KicsScanner` now constructs without them (a missing row leaves no install command and logs at debug), a test pins that, and the two row-reading tests skip with a stated reason until the rows exist.
- HIGH, checklist row 24, captured fixtures: `tests/test_data/scanners/kics/captured/` now holds `positive` and `negative` SARIF and JSON written by a real `kics scan` v2.1.20, with `README.md` recording the argv, the release and assets digests and one edit made after capture (two host paths in `positive.json`). New tests run the real captures through the scanner and check each result's level, severity and location.
- HIGH, checklist row 25, sandbox requirements: `tests/unit/plugin_modules/test_kics_sandbox_requirements.py` builds the policy with `build_scanner_policy` and checks the strict default, no network, and that `KICS_*` option variables are not passed in.
- Severity mapping over a captured report (checklist): `test_the_real_positive_capture_is_rated_per_query_and_located` and `test_the_real_capture_carries_a_critical_the_sarif_level_cannot_name`.

### License posture

KICS is Apache-2.0 (read from the LICENSE in the v2.1.20 release archive). The queries are a separate download and their license was not assessed (recorded in the license check). There is no GPL, AGPL or ELv2 material in this change. The ASH image does not bundle KICS in this change; the docs page describes a container-mode bundle that does not exist yet and should be reconciled by the integration lane.

### Central registration owed (not made here)

This change edits nothing outside the module, its tests, its fixtures and its docs page. An integration change needs:

1. `utils/tool_downloads.py`: a `kics` entry in `TOOL_VERSIONS` (`v2.1.20`), `_ASSET_TABLES` (the six `kics_2.1.20_<os>_<arch>` archives), the archive and executable digest tables, the pinned `assets` (queries and libraries) download that unpacks beside the binary, and `THIRD_PARTY_LICENSES["kics"]`.
2. `utils/scanner_names.py`: `"kics": "IAC"` in `SCANNER_TOOL_TYPES`.
3. `core/scanner_inventory.py`: the module in the community plugin list.
4. `tests/unit/walked_package.py`: `"plugin_modules/ash_kics_plugins"` in `PACKAGE_DIRS` (whole-tree collection stops with "not named in PACKAGE_DIRS" until it is there).
5. Shared register tests, each failing until its row exists: `CORPORA["kics"]` (`CorpusSpec("kics", sarif=("captured/*.sarif",))`), `_NATIVE_FIXTURES["kics"]`, `_DROPPED_FIXTURES["KicsScanner"]` (`("kics/captured/positive.json", "search_key", "aws_s3_bucket[b].acl=public-read")`), and the scanner count 22 to 23 in the two universe tests.

With `CORPORA["kics"]` added in a scratch copy, every `kics` cell of the corpus check read `ok`.

### Verification

Run on a Linux desktop from a repository copy of this branch (`uv sync --frozen --all-extras --group dev`, `env -i`, `-n 4`).

- KICS module tests and sandbox test: 77 passed, 2 skipped (the two tests that read the `kics` download rows, which skip with a stated reason until the rows exist), 0 failed.
- The same run plus the facets registry, totality, resource-id conformance, corpus consistency, operational consistency and vocabulary families: 555 passed, 2 skipped, 27 failed. Seven of the failures are the KICS rows in the central list above (universe count x2, platforms derived from the download table, tool type, dropped resource-id fixture row, corpus table agreement, `kics` corpus cell). The other 20 are corpus-consistency failures for other scanners that fail identically with the KICS module removed from the same extract (baseline 20 failed, 466 passed).
- `pytest --collect-only -q tests`: 74342 of 74387 collected, 1 error: the `PACKAGE_DIRS` row above.
- `ruff format --check` and `ruff check` over the whole tree pass (pre-commit, locked ruff).
