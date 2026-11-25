## Spectral alpha scanner plugin

Adds `ash_spectral_plugins`, an opt-in community scanner that runs [Spectral](https://github.com/stoplightio/spectral) (`spectral lint`) over the OpenAPI, Swagger and AsyncAPI descriptions in the scan target and reads its SARIF.

### What it scans

`spectral lint --ruleset=<ASH's own> --format=sarif --fail-severity=hint --ignore-unknown-format` over `**/*.{json,yaml,yml}`. Defects found: missing `operationId`, undefined path parameter, broken `$ref`, no `servers`, and the rest of `spectral:oas` and `spectral:asyncapi`. A tree with no JSON or YAML file is a clean skip.

### Tier

Alpha, opt-in. Loaded only when `ash_spectral_plugins` is listed in `ash_plugin_modules`. Built on main e0aac6c3aff.

### Facets declared

Both registers are declared in the scanner class, on the live shape:

- `facets` (`base/scanner_facets.py`): rule id, severity, file path, line range, column and message are MAPPED. `resource_id` and `resource_type` are N/A (a finding names a range in an API description, not a deployable resource), so no resource-scoped suppression can bind to a Spectral finding. Package, CVE, CWE, fingerprints, fix, remediation, snippet and tags are N/A with reasons from the captured report. `references` is DROPPED (the rule `helpUri` is in the report and not carried). `extras` is MAPPED (`issue_severity`).
- `operational_facets` (`base/scanner_operational_facets.py`): network NONE (bundled rulesets, strict sandbox), SARIF output, SAST over source, user-installed CLI, strict default sandbox, severity NATIVE, no tool-side silencing layer ASH passes, positional-only identity, operator-path rulesets, exit codes (0, 1), community opt-in tier, license not read.

### MUSTs and HIGHs fixed

| Row | Finding | Fix |
|---|---|---|
| MUST | The plugin was unconstructible: the unconditional `pinned_tool_install_commands("spectral")` raises `ToolNotProvisionableError` because `utils/tool_downloads.py` has no `spectral` row | Guarded in `setup_custom_install_commands`: no row means an empty install table and a debug line; `validate_plugin_dependencies` reports the missing binary. Tests: the scanner constructs, offers no install, and uses a row when one exists |
| MUST | `TestInstall` failed against the missing row; the timeout test regex did not match the real message (`timed out after '5' s`) | Install tests rewritten to the real state; regex fixed |
| HIGH | `ruleset_file` was resolved with `operator_path(..., outside_tree=False)`, so an operator-named path inside the scanned tree was accepted, and a JavaScript ruleset is code the tree could supply | `outside_tree=True`: an in-tree ruleset is refused with the shared warning and ASH's own ruleset is used. Option text, README and docs page updated. Test: `test_an_operators_ruleset_inside_the_scanned_tree_is_refused` |
| HIGH | No captured fixtures (checklist row 24); the oracle was a hand-trimmed transcription | `tests/test_data/scanners/spectral/captured/{positive,negative}.sarif` captured from the real Spectral 6.17.1 linux x64 binary on a desk; the severity mapping tests now run over them. The captured results equal the old transcription row for row |
| Row 25 | Sandbox policy asserted only as a ClassVar equality | `tests/unit/plugin_modules/test_spectral_sandbox_requirements.py` builds the policy through `build_scanner_policy` |
| Docs | README and docs page said the image bundles Spectral and `ash dependencies install` pins it; neither is true without the central row | Both say the operator installs the binary until the row lands |

### License posture

No recorded gate exists for Spectral in the license check, and nothing is vendored. The module neither bundles nor redistributes the binary, so the register says license "not read" rather than a recalled name. ASH installs nothing for it until the pinned row lands.

### Central registration owed (not made here)

An integration lane serializes these one-line edits:

1. `automated_security_helper/utils/tool_downloads.py`: a `spectral` row, version `v6.17.1`, base `https://github.com/stoplightio/spectral/releases/download`, bare executable assets with these sha256 digests (from the GitHub release API, linux x64 re-hashed locally):
   - `spectral-linux-x64` `0196c72234478e4e23df28b662afa7c9f80a47cfd31dc697e674151ad060bb35`
   - `spectral-linux-arm64` `730005664bbe95680f6b348790bb04da220e824b6e0a6768d16a1a988a86b31e`
   - `spectral-macos-x64` `42355e6dd861ba959164c6f24877fc77430001e263855e7379bb935e6566d836`
   - `spectral-macos-arm64` `ac0814fa86af3b57bb802f2290bb74e558b9522b9928ef16ac26c0d01ae6f9c5`
   - `spectral.exe` (windows amd64; no arm64 asset) `333705178ced9c7f815eed2fb5de99620643fd39a2373225e513eeb644648e57`

   When it lands, flip this module's `operational_facets` to `RuntimeKind.PINNED_BINARY` with `tool_versions_key="spectral"`, `ProvenanceSource.PINNED_RELEASE_BINARY` and `PLATFORMS` from `supported_platforms("spectral")`, and add a `THIRD_PARTY_LICENSES` entry read from the pinned upstream LICENSE.
2. `automated_security_helper/utils/scanner_names.py`: `"spectral": "SAST",` in `SCANNER_TOOL_TYPES`.
3. `automated_security_helper/core/scanner_inventory.py`: add `"automated_security_helper.plugin_modules.ash_spectral_plugins",` beside `ash_betterleaks_plugins` (line 73).
4. `tests/unit/walked_package.py`: add `"plugin_modules/ash_spectral_plugins",` to `PACKAGE_DIRS` (line 47). Without it, whole-tree collection errors with "not named in PACKAGE_DIRS".
5. `tests/unit/plugin_modules/test_scanner_facets_corpus_consistency.py`: `"spectral": CorpusSpec("spectral", sarif=("captured/*.sarif",)),` in `CORPORA`.
6. The shipped-scanner count assertions `== 22` become `== 23` (or the integrated total) in `test_scanner_facets_registry_totality.py`, `test_scanner_operational_facets_consistency.py` and `test_scanner_facets_corpus_consistency.py`.
7. Docs index (`docs/content/docs/plugins/community/index.md`), `docs/content/reference/scanners.md`, CHANGELOG, and the Dockerfile only if the image is to carry Spectral.

### Desk validation

dev-dsk-d14420e2, shipped as a repository, `uv sync --frozen --all-extras --group dev`, `env -i`, `-n 4`, basetemp in the lane under `/run/user/23503848/`. The register families (totality, resource-id conformance, corpus consistency, operational consistency, both vocabulary tests) and the Spectral module and sandbox tests ran with the central edits of items 2, 5 and 6 applied to the desk copy only:

- Spectral rows: 0 failed. The plugin's own tests, the sandbox test, the registry totality and operational consistency rows for `SpectralScanner`, the resource-id conformance row and the corpus consistency row for `spectral` all pass.
- Family total: 574 passed, 20 failed. All 20 failures are other scanners' rows in `test_scanner_facets_corpus_consistency.py` (declared-mapped cells with an empty or missing corpus on main); none names Spectral.
- Whole-tree collect smoke: 74324 collected, one collection error, the `PACKAGE_DIRS` item above (item 4).
- The desk extract was removed and its absence read back.
