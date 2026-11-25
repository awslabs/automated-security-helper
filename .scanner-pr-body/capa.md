## feat(plugins): capa alpha scanner plugin

Adds `ash_capa_plugins`, an opt-in alpha scanner that runs Mandiant's
[capa](https://github.com/mandiant/capa) (Apache-2.0) over the PE and ELF files in the
scan set and reports each matched capability.

### What it scans

capa reports what a compiled program can do ("create a process", "encrypt data using
RC4"), by matching its embedded rules against the program's functions. One
`capa -q -j -- <file>` run per executable; a file is selected only when its first bytes
are `MZ` or `\x7fELF`. Capabilities are not vulnerabilities, so no result rates above
LOW: a rule with an ATT&CK or MBC mapping is LOW (SARIF `note`), the rest INFO
(`none`). Library and sub-scope rules are not reported.

### Tier and posture

* Alpha, opt-in: enabled by listing `ash_capa_plugins` in `ash_plugin_modules`.
* Offline: rules and signatures are embedded in the standalone release, ASH passes no
  `-r` or `-s`, no network call at scan time. Sandbox declaration is the strict default.
* `success_exit_codes = {0}`: capa's 10 to 26 mean the file was not analyzed, so that
  file is a failed target (`targets_failed`, named in `errors`), not a finding.
* License: Apache-2.0, no gate; nothing is vendored or redistributed.

### Facets

Declares the facets register row (`facets`) and the operational row
(`operational_facets`, `scanner_name="capa"`), including the resource-identity
disposition (`resource_id`, `resource_type`: n/a, a capability belongs to a file) and the
operational dimensions: network none and offline unchanged, TOOL_JSON output, per-target
invocations, derived severity, positional-only identity, exit codes `(0,)`, community
tier. `references` is declared mappable-dropped (capa carries rule references, the
adapter does not write them).

### Fixes from the build review (RESULTS row for capa)

* MUST: the per-file exit code was read from the accumulated worst code, so one failed
  file made every later file fail. `exit_code` is reset before each run and the scan
  ends 0 unless every file failed. Test: a failure on the first file leaves the second
  read, with a fake that folds codes the way the real runner does.
* HIGH (row 20): stderr was kept out by overriding a private method. It now sets
  `quote_tool_stderr = False` and `unquoted_failure_tool_name`; the stderr test drives
  the base class's own response handling, which the fake had bypassed.
* HIGH (row 11): the install command raised when constructing the scanner, because
  capa has no pin in the download table. It now refuses with a reason (see below).
* HIGH (row 18/21/24): mapping tested over real capa 10.0.0 output, committed under
  `tests/test_data/scanners/capa/captured` with a README (host path scrubbed).
* HIGH (row 25): sandbox-requirements declaration tested through
  `build_scanner_policy`.
* A bounded-read guard flagged the 4-byte header read; it now uses `peek`.

### Central edits owed (not made here; an integration lane serializes them)

1. `utils/tool_downloads.py`: pin capa (version, per-platform asset names and sha256 for
   the v10 standalone release), add it to `TOOL_VERSIONS` and `THIRD_PARTY_LICENSES`.
   Then change the runtime row to `PINNED_BINARY` with `tool_versions_key="capa"`,
   provenance `PINNED_RELEASE_BINARY` and the platforms derived from the table.
   Verified on the capture host: the standalone release needs glibc 2.38 and cannot run
   on Amazon Linux 2023 (glibc 2.34); the pin's platform rows should say so.
2. `utils/scanner_names.py`: add `"capa": "SAST"` to `SCANNER_TOOL_TYPES`.
3. `tests/unit/plugin_modules/test_scanner_operational_facets_consistency.py`:
   universe count 22 to 23.
4. `tests/unit/walked_package.py`: add `plugin_modules/ash_capa_plugins` to
   `PACKAGE_DIRS` (a whole-tree collection error until then).
5. `tests/unit/plugin_modules/test_scanner_facets_corpus_consistency.py`: register capa's
   corpus (a prep converting `captured/*.json` to SARIF), or the mapped cells read
   "no committed fixture".
6. `TargetKind` has no executable-binary member; the row uses `SOURCE_CODE`, noted in
   `tool_type_note`.

### Desk validation

dev-dsk-d14420e2, repository ship, `uv sync --frozen --all-extras --group dev`,
`env -i`, lane under `/run/user/23503848/`, `-n 4`: capa tests plus `tests/unit/base`,
the operational-facets consistency file and the hadolint/guarddog sandbox file, 2008
passed, 2 failed, 110 skipped; both failures are central items 2 and 3 above. The
corpus-consistency file fails for capa (item 5) and, on this run, for 17 other scanners
that were not touched. Whole-tree collect: 74305 of 74350 collected, one error, item 4.
Extract removed, absence read back.
