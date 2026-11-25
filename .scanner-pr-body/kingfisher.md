## feat(plugins): Kingfisher alpha scanner plugin

### What it scans

[Kingfisher](https://github.com/mongodb/kingfisher) (MongoDB, Apache-2.0) finds secrets in files. ASH runs `kingfisher scan --git-history=none` over the scan target: the files as they are on disk, not git history. Flags were checked against Kingfisher v2.19.1. Every finding is CRITICAL; Kingfisher's confidence-based SARIF level is overwritten.

### Tier

Alpha, opt-in: loaded only when `automated_security_helper.plugin_modules.ash_kingfisher_plugins` is listed in `ash_plugin_modules`. A scan that does not list it is unchanged.

### Facets declared

- `facets` (mapping register): rule_id, severity (constant), file_path, line_range, column, message, fingerprints (`partialFingerprints.fingerprint`), snippet (`[REDACTED:<hash>]`) and extras mapped; resource, package, CVE/CWE, fix, remediation, references and tags n/a with reasons.
- `operational_facets`: network none (`--no-validate`, `--no-update-check`, offline strategy bundled, strict sandbox), SARIF output, secrets-contents target, user-installed CLI runtime (no pinned release), severity degraded (native level dropped), inline-ignore layer not honored (`--no-ignore`), identity unconfirmed (fingerprint stability not measured), exit codes 0/200/205, community opt-in, Apache-2.0 (source: upstream LICENSE at tag v2.19.1), no prerequisites.

### Findings fixed (RESULTS row: 0 MUST, 3 HIGH)

- HIGH, docs claimed a bundled container binary and a pinned download that do not exist: the docs page, module README and the license section now say ASH has no pinned release, the image does not include Kingfisher, and the operator installs it. The missing-binary warning follows `downloadable_tools()`.
- HIGH, no captured-fixture directory: `tests/test_data/scanners/kingfisher/captured/{positive,negative}.sarif` plus a README, now read by the unit tests and by the facets corpus gate.
- HIGH, unit suite red from the plugin-package glob: needs the central registrations below (not made here).
- Adapted to main: the two hand-written stderr overrides are replaced by the base class's `quote_tool_stderr` / `unquoted_failure_tool_name`.

### License posture

Apache-2.0, recorded clean. ASH does not bundle, download or redistribute Kingfisher; the live-validation option stays operator-only (`set_by_operator`), and the strict sandbox grants no network. No-install is deliberate until a pinned, digest-verified release table entry is added.

### Central registrations owed (not in this branch)

1. `automated_security_helper/core/scanner_inventory.py`, `_VENDORED_SCANNER_PLUGIN_PACKAGES`: add `"automated_security_helper.plugin_modules.ash_kingfisher_plugins",`.
2. `automated_security_helper/utils/scanner_names.py`, `SCANNER_TOOL_TYPES`: add `"kingfisher": "SECRETS",`.
3. `tests/unit/walked_package.py`, `PACKAGE_DIRS`: add `"plugin_modules/ash_kingfisher_plugins",`.
4. `tests/unit/plugin_modules/test_scanner_facets_corpus_consistency.py`, `CORPORA`: add `"kingfisher": CorpusSpec("kingfisher", sarif=("captured/*.sarif",)),`.
5. The scanner-count asserts `== 22` become `== 23` (corpus consistency, registry totality, operational facets consistency tests).
6. Optional: a `tool_downloads` pin for Kingfisher (releases, digests, license file) would let `runtime`/`platforms` move to a pinned binary.

### Desk counts (dev-dsk-d14420e2, py3.12.15, `-n 4`, env -i)

With edits 1-5 applied to the scratch copy only: kingfisher tests, facets vocabulary, registry totality, resource-id conformance, operational consistency and import-order families 571 passed, 0 failed in kingfisher rows; 20 failed in other scanners' corpus rows (for example `betterleaks.tags` mapped over an empty column), unrelated to this branch. Without edits 1-5 the central tests fail by design (23 vs 22 scanners, `KeyError: 'kingfisher'`, vendored list). Whole-tree collect: 74359/74404 collected, rc 0.

### Not verified

The captured SARIF is the capture recorded by the original build, moved byte-for-byte in content; Kingfisher was not re-run. Fingerprint stability across edits is unmeasured (identity declared unconfirmed).
