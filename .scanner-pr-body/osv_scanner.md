## OSV-Scanner alpha scanner plugin

Adds `ash_osv_scanner_plugins`, an opt-in (alpha) scanner module. Listing
`automated_security_helper.plugin_modules.ash_osv_scanner_plugins` in `ash_plugin_modules` turns it on; a scan that does not list it is unchanged.

### What it scans

`osv-scanner scan source --recursive` over the scan target. OSV-Scanner reads the lockfiles and manifests it recognizes (package-lock.json, yarn.lock, poetry.lock, uv.lock, go.mod, Cargo.lock, Gemfile.lock, composer.lock, pom.xml and others) and reports the matching OSV advisories, one result per vulnerable package and advisory. Tool type SCA. It overlaps the builtin grype and trivy-repo scanners where they read the same lockfiles.

### Tier and facets

Community opt-in (alpha). Declared under the facets register:

- mapping facets: rule_id, severity, file_path, message, taxonomy_cve and fingerprints are MAPPED; line_range and column are n/a (the captured report has no region); resource_id and resource_type are n/a (a package in a lockfile is not a deployable resource); package name, version and path are n/a (named only inside the message text, which the adapter does not parse); tags is n/a (the report carries none; the adapter adds `sca` and `security`).
- operational facets: network is a content fetch of the OSV database, `--offline` degrades to a previously downloaded local database; SARIF output; dependency-lockfile targets; user-installed CLI runtime; severity derived (rule `security-severity`, else the SARIF level); the tree's `osv-scanner.toml` is never honored (ASH passes `--config=<empty file>`); success exit codes 0, 1, 128; lockfile prerequisite; upstream license "not read".

### Findings fixed (RESULTS row `osv_scanner`)

- MUST (integration dependency): the install-command validator called `pinned_tool_install_commands("osv-scanner")`, which raises `ToolNotProvisionableError` for a tool with no download row, so the scanner could not be constructed. It now constructs with no install commands, the dependency hint says ASH does not install it, and the call fills the table by itself once the row exists. Pinned by `TestInstallCommands`.
- HIGH, no captured fixture (checklist rows 18, 21, 24): a real OSV-Scanner v2.7.1 report is committed in `tests/test_data/scanners/osv_scanner/captured/` (positive.sarif, README.md), taken from the linux/amd64 release asset checked against its published SHA256. The tests now rate every result of the real report from its rule score. The capture also corrected two claims written from the documentation: OSV-Scanner writes absolute `file://` URIs (now rewritten target-relative under the scan target), and exit 128 writes no report file.
- HIGH, no sandbox policy test (row 25): `TestSandboxPolicy` builds the policy with `build_scanner_policy` and checks that the declared network is granted online and withheld under offline.
- Docs and README no longer say the image ships OSV-Scanner or that `ash dependencies install` fetches it.

### License posture

OSV-Scanner is Apache-2.0 and has no license or service gate. ASH does not install or redistribute it.

### Central registration owed (not made here)

Edits to shared files for the integration lane; none made in this branch:

- `utils/tool_downloads.py`: a pinned `osv-scanner` asset row (v2.7.1 SHA256s from the release's SHA256SUMS). With it, flip `runtime.kind` to `PINNED_BINARY` with `tool_versions_key="osv-scanner"`, `platforms.provisionable`, and provenance `PINNED_RELEASE_BINARY`.
- `utils/scanner_names.py` `SCANNER_TOOL_TYPES`: `"osv_scanner": "SCA"`.
- `utils/content_databases.py` `SCANNERS_WITHOUT_CONTENT_DATABASE` (or a `CONTENT_DATABASES` entry): `osv_scanner`, a CACHE_FLAGS scanner.
- `tests/unit/plugin_modules/test_scanner_facets_corpus_consistency.py` `CORPORA`: `"osv_scanner": CorpusSpec("osv_scanner", sarif=("captured/*.sarif",))`; the scanner counts (22) in this file, the totality test and the operational consistency test move to 23.
- `walked_package.PACKAGE_DIRS`, the vendored-plugin list and the other PATTERN rows 26-34 registrations.

### Desk validation (dev-dsk-d14420e2, repository clone, `uv sync --frozen --all-extras --group dev`, `env -i`, `-n 4`)

- The module's tests: 66 passed.
- Facets registry, corpus, resource-id conformance, operational consistency and both vocabulary families: 573 passed in total with the module tests, 26 failed. 21 of the failures are the corpus gate (20 already red on main, plus `osv_scanner`, which fails with `KeyError` for want of its `CORPORA` row). The other five are the central registrations above: the three scanner-count assertions, `test_content_database_join_agrees_both_ways` and `test_tool_type_is_one_story_across_four_declarations` for this scanner. With a throwaway `CORPORA` row and tool-type entry, the corpus gate reads every `osv_scanner` cell ok against the real capture.
- Whole-tree `pytest --collect-only`: 74329 of 74374 collected, one collection error: `not named in PACKAGE_DIRS` (the central `walked_package` entry).
- `ruff format --check` and `ruff check` pass (the locked ruff, via the repository hooks). Marker scan zero. Whole-range author and committer audit: one noreply identity.
