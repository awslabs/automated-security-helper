## bundler_audit: alpha community scanner for known-vulnerable gems

### What it scans

`bundler-audit check` reads the `Gemfile.lock` at the root of the scan target and matches each locked gem version against the ruby-advisory-db advisory database. It also reports a gem source fetched over `git://` or `http://`. Only the root lockfile is read; a target with no root `Gemfile.lock` (or a symlinked one) is skipped, not failed. The tool writes JSON; the plugin converts it to SARIF.

### Tier

Alpha, opt-in community plugin module (`automated_security_helper.plugin_modules.ash_bundler_audit_plugins`, listed in `ash_plugin_modules`). `SKIP_OFFLINE` because the advisory database is a git clone or pull over the network.

### Facets declared

Mapping register (`facets`): MAPPED rule_id, severity, file_path, line_range, message, package_name, package_version, package_path, taxonomy_cve, fingerprints, tags, extras. DROPPED fix_available (`advisory.patched_versions`, kept in the message) and references (`advisory.url`, written as the rule helpUri). N/A column, resource_id and resource_type (a gem is a package locator, not a deployable resource), taxonomy_cwe, remediation_text, snippet.

Operational register (`operational_facets`): content fetch of the advisory database (vuln_db), offline not_run, sandbox network online, tool JSON converted to SARIF, dependency lockfile target (SCA), user-installed CLI runtime (ruby, gem), native severity, one tool-side silencing layer (`.bundler-audit.yml`, not honored: ASH passes its own `ignore: []` config), stable computed fingerprint, exit codes 0 and 1, community opt-in, lockfile prerequisite.

### MUSTs and HIGHs fixed

RESULTS row for bundler_audit: 0 MUST, 1 HIGH.

* HIGH, checklist row 24 (no captured fixtures): added `tests/test_data/scanners/bundler_audit/captured/` with a real bundler-audit 0.9.3 run (positive: 7 rexml advisories plus a `git://` source, exit 1; negative: clean lockfile, exit 0), the SARIF the adapter makes of each, the input lockfile, and a README recording argv, tool and database versions. Tests assert the committed SARIF equals the converter's output over the capture, the severity of every result, and the lockfile line of every result (checklist row 18).
* Row 25 (sandbox-requirements test): `test_bundler_audit_sandbox_requirements.py` builds the policy through `build_scanner_policy` and asserts the network grant, the advisory-database cache path, the offline withholding of the network, and that no credential or config variable passes in.
* One existing behavior test asserted the SARIF driver name `bundler-audit`; main's base class now sets the driver name to the scanner config name, so it asserts `bundler_audit`.

### License posture

bundler-audit is GPL-3.0-or-later (gemspec `licenses` and `COPYING.txt`, read from the 0.9.3 gem). It is never imported, vendored or bundled in the image: ASH runs it as a separate process, and the only install path is `ash dependencies install` running `gem install bundler-audit -v 0.9.3 --user-install` on the user's request. The register therefore declares a user-installed CLI with no provisionable platforms. A recorded license gate of "invoked-only, user installs it" is deliberate and kept.

### Central registration owed (not made here)

This module touches no file outside itself. An integration lane owes these edits, each of which today fails a test with the module present (measured on the desk: 6 new failures, all in this list):

1. `utils/scanner_names.py` `SCANNER_TOOL_TYPES`: add `"bundler_audit": ScannerToolType.SCA` (fails `test_tool_type_is_one_story_across_four_declarations`).
2. `tests/unit/plugin_modules/test_scanner_facets_corpus_consistency.py`: add `"bundler_audit": CorpusSpec("bundler_audit", sarif=("captured/*.sarif",))` to `CORPORA`, and raise the scanner count in `test_the_registry_and_the_corpus_table_agree`.
3. `tests/unit/plugin_modules/test_scanner_facets_registry_totality.py` and `test_scanner_operational_facets_consistency.py`: raise the shipped-scanner count; add `bundler_audit` to the expected `NOT_RUN` list in `test_the_service_upload_scanner_is_the_one_that_skips_offline`.
4. The whole-tree collect error `not named in PACKAGE_DIRS` (`plugin_modules/ash_bundler_audit_plugins`): add the package to the `PACKAGE_DIRS` list the collection-time test reads.
5. `.ash/.ash_community_plugins.yaml` and the other shared discovery, docs index and generated-reference files named in PATTERN rows 26-37.

The module-local tests `test_bundler_audit_captured_and_facets.py` run the corpus gate's own `judge` over this scanner's captured SARIF for every facet, so the declarations are checked until the central table lists it.

### Desk validation (dev-dsk-cbc4ff77, pinned known_hosts, repository ship, `uv sync --frozen --all-extras --group dev`, `env -i`, lane under `/run/user/23503848/`, `--basetemp` in the lane, `-n 4`)

* bundler_audit module tests: 104 passed, 0 failed.
* Facets registry, corpus, resource-id conformance and operational consistency families plus the module: 572 passed, 26 failed. The same families without this module: 455 passed, 20 failed. The 20 are the other scanners' corpus-consistency cases and fail on main alike on the desk; the 6 extra are the central-registration items above.
* Whole-tree `pytest tests/unit --collect-only -q`: 72,865 tests collected, 1 collection error (item 4 above).
* Real run: bundler-audit 0.9.3 against ruby-advisory-db `c87703e` produced the committed captures. Extract removed, absence read back.
* `ruff format --check` and `ruff check` clean; marker scan 0; `origin/main..HEAD` author and committer one noreply line.
