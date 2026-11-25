## cargo-audit alpha scanner plugin

Adds `ash_cargo_audit_plugins`, an alpha, opt-in community scanner for Rust dependencies. It runs `cargo audit --json --file=<Cargo.lock>` once per `Cargo.lock` in the scan set and converts the RustSec report to SARIF. It reads lockfiles, not source.

Tier: alpha, community, opt-in (listed in `ash_plugin_modules`).

### Facets declared

Both registers are declared on the class (`facets`, `operational_facets`).

- Mapped: rule id (advisory id), severity (CVSS v3 vector scored by the adapter, HIGH when absent; warnings by kind), file path, line range (constant line 1), message, fingerprints (`cargo-audit/advisory-fingerprint`), tags, extras.
- Resource identity: not applicable (a crate in a lockfile is not a deployable resource), for both `resource_id` and `resource_type`.
- Dropped but mappable: package name and version, CVE aliases (`advisory.aliases`), fix availability and remediation (`versions.patched`), references (`advisory.url`).
- Operational: content fetch of the advisory feed, sandbox network online, offline strategy cache-flags (`--no-fetch`), one run per lockfile, user-installed CLI, severity derived, exit codes 0 and 1, prerequisite a lockfile.

### Findings fixed from the build review

- HIGH, tree-supplied tool config: cargo-audit reads `./.cargo/audit.toml` from its working directory (read from cargo-audit `config.rs`, `AuditConfig::load`; there is no `--config` flag), so a repository could ignore advisories. The tool now runs in a directory outside the scanned tree through `_subprocess_cwd`; `~/.cargo/audit.toml` still applies. Test: the call's cwd is outside the tree and holds no `.cargo/audit.toml`.
- Checklist row 7: the lockfile is one `--file=<absolute path>` token.
- Raising install commands: `pinned_tool_install_commands("cargo-audit")` raised at construction because there is no pinned asset. Removed; cargo-audit is a user-installed CLI and the missing-tool hint names `cargo install cargo-audit --locked`.
- Checklist row 25: sandbox policy test through `build_scanner_policy` (online grants the network and the advisory database directory, offline grants no network).
- Added `nothing_to_scan_reason` (a tree without a lockfile reads SKIPPED, not MISSING), a test for each register mirror, and a flat-row conformance test over the converter output.
- Fixed `test_report_is_written_and_a_stale_one_removed`, which looked in the wrong directory and could not fail.

### Not met

- Checklist rows 18, 21 and 24 (a real captured report): cargo-audit is on no desk and cannot be installed under the frozen toolchain, so the tests use documents written from the rustsec `Report` types. A capture from a host that has the tool is owed; with it the corpus table below can go in.

### License posture

cargo-audit is Apache-2.0 OR MIT (both alternatives are permitted). ASH neither installs nor redistributes it, so nothing is vendored, and the register records the upstream license as "not read" until a pinned LICENSE read is cited.

### Central registration owed (integration lane)

No file outside the module and its tests was edited. These shared edits are needed, found by running the gates:

- Add `ash_cargo_audit_plugins` to `PACKAGE_DIRS` (whole-tree collection fails with `not named in PACKAGE_DIRS`).
- `utils/scanner_names.py` `SCANNER_TOOL_TYPES`: add `cargo-audit` as SCA (`test_tool_type_is_one_story_across_four_declarations`, and the register-versus-table check in `test_the_universe_is_the_twenty_two_shipped_scanners`).
- `utils/content_databases.py`: add a `CONTENT_DATABASES` entry for the RustSec advisory database (`~/.cargo/advisory-db`) (`test_content_database_join_agrees_both_ways`).
- `tests/unit/plugin_modules/test_scanner_facets_corpus_consistency.py`: add a `cargo-audit` corpus spec once a captured fixture exists.
- Bump the scanner-count controls from 22 in `test_scanner_facets_registry_totality.py` and `test_scanner_operational_facets_consistency.py`.

### Desk validation

Desk d14420e2, repository extract, `uv sync --frozen --all-extras --group dev`, `env -i`, `-n 4`: the module's own tests all pass (68 module tests green; 575 passed across the module, registry totality, corpus, resource-id conformance, operational consistency and vocabulary families). The 26 failures are the central items above (count 22, corpus table, content database, tool-type table) plus the corpus-gate failures that every other scanner row shows alike on this venue. The whole-tree collect smoke stops at the missing `PACKAGE_DIRS` entry, then 74331 of 74376 collected.
