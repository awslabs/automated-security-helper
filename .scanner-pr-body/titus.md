## Titus alpha scanner plugin

Adds `ash_titus_plugins`, an opt-in community scanner for secrets, on the facet model.
It is alpha tier: it runs only when `automated_security_helper.plugin_modules.ash_titus_plugins`
is listed in `ash_plugin_modules`.

### What it scans

[Titus](https://github.com/praetorian-inc/titus) (Praetorian, Go port of Nosey Parker) over the
scan target's files, not git history:

```
titus scan --format=sarif --output=:memory: --accessibility=private --context-lines=0 -- <path>
```

SARIF comes from stdout. No `--validate`, `--score-scope`, `--rules`, `--ruleset`, `--ignore`,
`--git` or token flag is ever passed, so nothing calls out and nothing in the scanned tree selects
rules. Matched text is replaced with `REDACTED`. Severity is derived from Titus' 0-10
`security-severity` score (8+ CRITICAL, 6+ HIGH, 4+ MEDIUM, 2+ LOW, else INFO). Only exit code 0
counts as a finished run.

### Facets declared

- `facets` register row: rule_id, severity, file_path, line_range, column, message, fingerprints
  (`titusLocation/v1`) and snippet MAPPED; extras MAPPED (`issue_severity`); resource_id and
  resource_type N/A (a secret names a file location, not a deployable resource); package_*,
  taxonomy_cve, taxonomy_cwe, fix_available, remediation_text, references, tags N/A with reasons
  read from the captured report. The corpus gate observes the cells over the captured fixture.
- `operational_facets` row: no network (BUNDLED, sandbox network none), SARIF output, targets
  `secrets_contents`, severity DERIVED, identity STABLE_NATIVE, exit codes `(0,)`, tier
  community opt-in, runtime `USER_INSTALLED_CLI` (see "Owed" for the pin).

### Findings fixed (RESULTS row: 20/24 applicable rows, 1 MUST, 2 HIGH)

- MUST, committed scan() tests failing and raising install commands: construction raised because
  `pinned_tool_install_commands("titus")` has no table entry. Install commands are now built only
  when the pin table lists titus; otherwise construction succeeds with none. Two tests pin both
  branches. The stale stderr plumbing (two overrides that duplicated base behavior) is replaced by
  the base `quote_tool_stderr = False` / `unquoted_failure_tool_name = "titus"` mechanism, with a
  control test showing the flag is what keeps stderr out of `errors`.
- HIGH, no captured fixture (checklist rows 18 and 24): Titus v1.3.0 (`titus-linux-amd64`, sha256
  `74c665b8...fdabc`, equal to the release's `checksums.txt`) was run on a desk under `env -i`; its
  real output is committed under `tests/test_data/scanners/titus/captured/` with a README naming the
  three edits made to it. `TestCapturedReport` drives the adapter over it (severity bands, location,
  redaction, fingerprint). The real run showed `properties.absolute_path` (the scanned file's
  absolute path), which the report now drops.
- HIGH, no sandbox-requirements test (row 25): `tests/unit/plugin_modules/test_titus_sandbox_requirements.py`
  builds the policy with `build_scanner_policy` and asserts the strict default and that
  `GITHUB_TOKEN`, `GITLAB_TOKEN` and AWS variables are not passed in.
- Docs: the earlier docs page claimed a pinned download and a container-image copy that do not
  exist, and 487 rules (the real report lists 502). Corrected; the page is staged, see below.

### License posture

The plugin docs written earlier state Apache-2.0 for Titus; that was not re-read from the pinned
LICENSE here, so the register records `upstream_license` as "not read" because no
pinned LICENSE read was made. There is no license or service gate and no entry in the license-check
record for it, so no no-install gate applies. ASH does not redistribute the binary.

### Owed to the integration lane (central edits not made here)

1. `utils/tool_downloads.py`: a `titus` entry. v1.3.0 publishes bare executables for linux and
   darwin (amd64, arm64) and windows/amd64 (no windows/arm64); add `TOOL_VERSIONS["titus"]`,
   `_TITUS_ASSETS`, `_ASSET_TABLES`, `_RELEASE_BASE_URLS`, `_BARE_EXECUTABLE_TOOLS`, the pinned
   digests and `THIRD_PARTY_LICENSES["titus"]`. The scanner then installs through the pinned table
   unchanged; flip `operational_facets.runtime` to `PINNED_BINARY` with `tool_versions_key="titus"`,
   `platforms.provisionable` to the derived set and `provenance.source` to `PINNED_RELEASE_BINARY`.
2. `utils/scanner_names.py`: `"titus": "SECRETS"` in `SCANNER_TOOL_TYPES`.
3. `tests/unit/plugin_modules/test_scanner_facets_corpus_consistency.py`:
   `"titus": CorpusSpec("titus", sarif=("captured/*.sarif",))` in `CORPORA`.
4. `tests/unit/plugin_modules/test_scanner_operational_facets_consistency.py`: universe count 22 to 23.
5. `tests/unit/walked_package.py`: `"plugin_modules/ash_titus_plugins"` in `PACKAGE_DIRS`.
6. `core/scanner_inventory.py`: add the module beside `ash_betterleaks_plugins`.
7. Docs: add `.scanner-pr-body/titus-docs-page.md` as
   `docs/content/docs/plugins/community/titus-plugin.md`, plus the homepage community count and
   links, the plugins overview, the coverage tables and the page's claims in
   `tests/unit/docs/test_page_claims.py` (the doctest ratchet refuses a new page with no mechanism).

Until those land, the whole-tree suite has expected reds that name titus (listed below).

### Desk validation (dev-dsk-cbc4ff77, lane under /run/user/23503848, repository ship, `uv sync --frozen --all-extras --group dev`, `env -i`, `-n 4`)

- Titus module tests plus sandbox test: 74 passed, 0 failed.
- Facets families (registry totality, corpus consistency, resource-id conformance, operational
  consistency, both vocabulary tests) with items 2, 3 and 4 applied on the desk copy only: 585
  passed, 22 failed, none naming titus. The 22 are the same set with and without those desk edits
  and cover other scanners (grype, semgrep, syft, npm-audit, opengrep, trivy, zizmor, guarddog,
  ferret-scan, snyk-code and others).
- Without the desk-only edits the titus-named failures are exactly three: corpus-consistency
  `[titus]` (item 3), `test_the_universe_is_the_twenty_two_shipped_scanners` (item 4) and
  `test_tool_type_is_one_story_across_four_declarations[TitusScanner]` (item 2).
- Whole-tree collect smoke: 74376/74421 collected with item 5 applied on the desk copy; without it,
  one collection error naming `PACKAGE_DIRS`.
- `tests/unit/docs` with the page present: 4 failed (the three docs listings and the doctest ratchet,
  all item 7); the page was moved out of `docs/` to `.scanner-pr-body/` for that reason.
- ruff format --check and ruff check green (pre-commit); marker scan zero; whole-range audit
  `origin/main..HEAD` one noreply line.
