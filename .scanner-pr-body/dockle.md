## Dockle alpha scanner plugin (`ash_dockle_plugins`)

### What it scans

Dockle lints ONE container image (CIS Docker Benchmark and image best practices):
user, credential-looking files and variables, HEALTHCHECK, content trust. It scans an
image named by the operator (`options.image`, pulled by Dockle) or a saved image
tarball (`options.image_tarball`, no network), not the scanned source tree. With
neither option set the scanner logs why and does nothing. Options written by a config
inside the scanned tree or by an MCP client are ignored with a warning.

### Tier

Alpha, opt-in: it runs only when `automated_security_helper.plugin_modules.ash_dockle_plugins`
is listed in `ash_plugin_modules`. Offline strategy `SKIP_OFFLINE`. Success exit codes
`{0}` (no `--exit-code` is passed; any other exit is a failure). Sandbox network need
follows the operator's option (`network_requires_grant`).

### Facets declared

`facets` (mapping register) and `operational_facets` (operational register), checked
against a real capture:

- mapped: `rule_id`, `severity` (FATAL, WARN, INFO and none become HIGH, MEDIUM, LOW
  and INFO), `file_path` (an in-image path or `metadata`), `message`, `extras`
- mappable but dropped: `references` (rule `helpUri`)
- n/a with reasons: resource id and type (the image reference is an image locator,
  not a resource id), package fields, CVE and CWE, fingerprints, fix, remediation,
  snippet, line, column, tags (none in the native output)
- operational: target kind `container_image`, tool type `CONTAINER`, pinned binary
  runtime, community opt-in tier, upstream license `not read`

### Findings fixed

- MUST: `test_a_timeout_fails_the_scan_and_says_so` failed against the scanner's own
  message (`timed out after '5' s`); the test now matches it.
- HIGH: severity mapping and report tests ran over a hand-written report. Added
  `tests/test_data/scanners/dockle/captured/` with REAL Dockle 0.4.15 output
  (`positive.sarif` with all four levels, `negative.sarif`), the two `docker save`
  tarballs they came from, a stdlib builder script and a README. `TestCapturedReports`
  maps both.
- HIGH: no sandbox-requirements test. Added
  `tests/unit/plugin_modules/test_dockle_sandbox_requirements.py` (grant gating, the
  `DOCKLE_` prefix, a credential-shaped name under it).
- Facets: corpus read corrected `file_path` to mapped and `tags` to n/a.

### License posture

Dockle's GitHub license API reads Apache-2.0 and its README mentions AGPL in a badge;
the registry carries `not read` until a named-license read settles it. Nothing is
vendored. The scanner installs only from a pinned release asset (Linux and macOS
64-bit and ARM64 exist upstream; no Windows asset), and no install is attempted until
the shared table has a `dockle` row.

### Central edits owed (not made here; the integration lane serializes them)

Required for the module to import and for the register tests, found on desk:

1. `base/scanner_operational_facets.py`: remove the `TargetKind.CONTAINER_IMAGE` entry
   from `UNCLAIMED_TARGET_KINDS` (without this, importing the plugin raises a
   `ValidationError` in `TargetsFacet`) and add
   `ScannerToolType.CONTAINER: frozenset({TargetKind.CONTAINER_IMAGE})` to
   `TOOL_TYPE_SERVED_BY`.
2. `utils/scanner_names.py`: `"dockle": "CONTAINER"` in `SCANNER_TOOL_TYPES`.
3. `utils/tool_downloads.py`: a `dockle` row (version `v0.4.15`; assets
   `dockle_0.4.15_Linux-64bit.tar.gz`, `Linux-ARM64`, `macOS-64bit`, `macOS-ARM64`;
   digests from the release `checksums.txt`; license entry), then set
   `platforms.provisionable` in the facets declaration to the derived list
   (`test_platforms_are_derived_from_the_download_table` fails until both agree).
4. `tests/unit/walked_package.py`: add `plugin_modules/ash_dockle_plugins` to
   `PACKAGE_DIRS` (collection-time assertion).
5. Counts and tables in tests: `test_scanner_facets_corpus_consistency.py` (22 to 23
   and `"dockle": CorpusSpec("dockle", sarif=("captured/*.sarif",))`),
   `test_scanner_facets_registry_totality.py` (22 to 23),
   `test_scanner_operational_facets_consistency.py` (22 to 23; `dockle` in the
   skipped-offline list; an optional `_NATIVE_FIXTURES` row for
   `dockle/captured/positive.sarif`).
6. Registration surfaces the other plugins appear in: `core/scanner_inventory.py`,
   `Dockerfile` `ASH_COMMUNITY_PLUGIN_MODULES`, `docs/content/docs/plugins/community/index.md`,
   `docs/content/reference/scanners.md` (generated).

### Desk validation (dev-dsk-d14420e2, repository extract, `uv sync --frozen --all-extras --group dev`, `env -i`, `-n 4`)

With the central edits 1, 2, 4 and 5 overlaid on the extract only: the dockle test
files (behavior, sandbox) and the facets vocabulary, registry totality, resource-id
conformance and operational consistency families, 569 passed, 0 failed in dockle
families except `test_platforms_are_derived_from_the_download_table[DockleScanner]`
(needs edit 3). The 20 `test_declared_facets_agree_with_the_observed_corpus` failures
for other scanners are identical on a clean `origin/main` extract (20 failed, 21
passed there). Whole-tree collect smoke: 72,820 tests collected, 1 error (edit 4).
