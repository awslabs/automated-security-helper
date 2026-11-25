## feat(plugins): cargo-deny alpha scanner plugin

### What it scans

[cargo-deny](https://github.com/EmbarkStudios/cargo-deny) checks a Rust project's
`Cargo.lock` against the RustSec advisory database and, with an operator config, a
license, ban and source policy. The scanner runs it once per `Cargo.toml` that has a
`Cargo.lock` beside it (skipping `target/`), reads the `--format=json` diagnostics from
stderr and converts them to SARIF. cargo-deny's own SARIF writer is experimental and is
not used.

### Tier

Alpha, opt-in community plugin: it loads only when
`automated_security_helper.plugin_modules.ash_cargo_deny_plugins` is listed in
`ash_plugin_modules`. A scan that does not list it is unchanged.

### Facets declared

- Mapping register (`ScannerFacets`): rule id, severity, message, package name and
  version and extras are MAPPED. File path, line, column, package path, resource id and
  type, CWE, fingerprints, fix, remediation and snippet are N/A with reasons. CVE
  taxonomy, references and tags are mappable-but-dropped. No `resource_id` is mapped, so
  no suppression is bound to a crate locator.
- Operational register (`ScannerOperationalFacets`): content fetch (advisory feed,
  package metadata), `SKIP_OFFLINE`, sandbox network online, tool JSON output,
  dependency-lockfile targets typed SCA, user-installed CLI needing `cargo`,
  native severity, operator-only deny.toml silencing, computed stable fingerprint,
  exit codes 0..15 (check bitset), community opt-in tier, lockfile and manifest
  prerequisites.

### MUST and HIGH rows fixed

- MUST: `scan()` read `self.exit_code`, which the base's `_run_subprocess` FOLDS (worst
  so far) across runs, as if it were the current run's code. A first project that
  failed with 101 made every later project read 101. The accumulator is reset before
  each run, and the scan's recorded code is the OR of the runs' check bitsets. The test
  fake now folds like the real method, so it can fail on this; two regression tests
  cover both orders.
- HIGH: constructing the scanner raised, because a model validator called
  `pinned_tool_install_commands("cargo-deny")`, for which no pin exists. The validator
  is removed (see License posture); the autouse monkeypatch that hid this is removed
  too, and tests construct the scanner unpatched.
- HIGH, checklist row 24: captured fixtures committed under
  `tests/test_data/scanners/cargo-deny/captured/` (positive, negative, no-lock, with a
  README) and exercised end to end, including the severity mapping over the captured
  advisory.
- HIGH, checklist row 25: sandbox policy test
  (`test_cargo_deny_sandbox_requirements.py`) built through `build_scanner_policy`.

### License posture

ASH does not install cargo-deny. No pinned release asset exists for it in
`utils/tool_downloads.py`, and adding one is a shared-file edit outside this module, so
the scanner declares no install commands and a missing binary is reported with a
user-install hint (`cargo install --locked cargo-deny`). The upstream license is
recorded as "not read" in the register: no pinned upstream LICENSE read backs a value.
Nothing is vendored.

### Central registration owed (integration lane)

Not edited here, by instruction:

- `automated_security_helper/utils/scanner_names.py`: add `"cargo-deny": "SCA",` to
  `SCANNER_TOOL_TYPES` (the operational consistency test requires the register's
  scanner names and this table to agree).
- `tests/unit/walked_package.py`: add `"plugin_modules/ash_cargo_deny_plugins"` to
  `PACKAGE_DIRS` (the whole-tree collect smoke fails on "not named in PACKAGE_DIRS").
- The facets corpus table in `tests/unit/plugin_modules/test_scanner_facets_corpus_consistency.py`
  needs a `cargo-deny` row pointing at `tests/test_data/scanners/cargo-deny/captured/`
  (the committed fixtures here), or the five mapped cells read "no committed fixture".
- Shared tests that pin the scanner count (the "twenty-two shipped scanners" universe in
  the registry totality and operational consistency tests, and the exact
  `skip_offline` list `["npm-audit", "snyk-code"]`, which gains `cargo-deny`) move with
  the combined set.
- Optional, later: a pinned `cargo-deny` entry in `utils/tool_downloads.py` (version,
  per-platform SHA256, license entry), after which the module can declare
  `pinned_tool_install_commands("cargo-deny")` again.

### Desk validation

Desk dev-dsk-cbc4ff77, repository extract, `uv sync --frozen --all-extras --group dev`,
`env -i`, `-n 4`, Python 3.14:

- Module tests (`tests/unit/plugin_modules/ash_cargo_deny_plugins`): 98 passed, 0 failed.
- Module plus facets families (totality, resource-id conformance, corpus consistency,
  operational consistency, both vocabulary tests): 605 passed, 26 failed. Every failure
  is one of the central items above (scanner count, `SCANNER_TOOL_TYPES` key, corpus
  table, `skip_offline` list) or its cascade through the corpus table; the module's own
  families, including the prerequisites and nothing-to-scan test, pass.
- Whole-tree collect smoke: 74361 of 74406 collected, one error: `PACKAGE_DIRS` (above).
- ruff format --check and ruff check: green. Extract removed, absence read back.
