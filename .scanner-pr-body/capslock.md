## Capslock alpha scanner plugin

### What it scans

Capslock (google/capslock) reports which privileged operations (files, network,
exec, unsafe, cgo, and others) a Go package can reach through its transitive
calls. The plugin runs it once per Go module (`go.mod` directory) in the target
and turns each reported capability into one SARIF result. Every result is INFO
(SARIF level `none`, kind `informational`): a capability is an inventory of what
the code can do, so the scanner is a review aid and does not fail a scan on its
own.

### Tier

Alpha, opt-in. Loaded only when `ash_capslock_plugins` is listed in
`ash_plugin_modules`.

### License posture

Capslock publishes no release binaries and ASH installs and redistributes
nothing. The user installs it with
`go install github.com/google/capslock/cmd/capslock@latest`. That no-install
design is deliberate and unchanged. The facets register records the upstream
license as "not read": the license check has no Capslock row, and the module
docstring's BSD-3-Clause statement comes from the project README, not a pinned
LICENSE read.

### Facets declared

`facets` (mapping register) and `operational_facets` (operational register) are
declared on the class.

- Mapped: rule id (`capabilityName`), severity (adapter constant INFO), file path,
  line, column (first call site inside the target, else `go.mod`), message, tags,
  extras.
- Dropped (native field exists, ASH discards it): package name
  (`packageName`, kept only in `capslock_package`) and package path
  (`packageDir`).
- Resource identity: `resource_id` and `resource_type` are n/a with a reason (a
  finding is a Go package's reachable capability at a call site, not a
  deployable resource).
- n/a with reasons: package version, CVE, CWE, fingerprints, fix available,
  remediation text, snippet, references.
- Operational: runtime user-installed CLI (`capslock`, `go`), one invocation per
  module, no network, severity constant, positional-only identity, success exit
  code `{0}` (from `cmd/capslock/capslock.go`), prerequisite `go.mod`.

### Findings fixed

From the build program RESULTS row (capslock, 20 of 23 applicable rows met):

- MUST: `scan()` accepted `global_ignore_paths` and never read it, so a Go
  module under an operator-ignored path was still analyzed. Fixed with
  `drop_ignored_modules`, which matches each module's `go.mod` path and directory
  with `ignore_path_matches` (a path ending in `/` names a directory). Tests cover
  a directory ignore, a `go.mod` path ignore, no ignores, an unrelated ignore, the
  root module, and the `scan()` path (a module is not run; every module ignored
  runs nothing).
- HIGH (row 25): no sandbox-requirements test. Added one built on
  `build_scanner_policy`: the strict default is declared, no network, and the
  shell's `GOFLAGS`, `GOPROXY` and `GOMODCACHE` do not reach the sandboxed tool.
- HIGH / row 24 (captured fixtures): PARTLY met. No Go toolchain is on the build
  host and Capslock has no release binaries, so no real report could be
  captured. Committed instead: `tests/test_data/scanners/capslock/schema_derived/`
  (positive and negative reports written from the protobuf schema, with a README
  that says in its first line they are not captured output), and a row-by-row
  severity test over the positive fixture. Replace them with real captures when a
  Go toolchain is available.
- Row 18 (severity tested over a real captured report): the same limit. The
  severity mapping is tested row by row over the schema-derived report.
- A committed test of the report-level check (`test_severity_and_level_agree_on_every_result`)
  read `.value` on a field the model returns as a plain string; it now reads both
  shapes.

### Central registrations owed (not made here)

The plugin touches no shared file. An integration lane owes these edits, each
confirmed by a failing test on the validated tree:

1. `automated_security_helper/utils/scanner_names.py`, `SCANNER_TOOL_TYPES`:
   add `"capslock": "SAST",`.
2. `tests/unit/walked_package.py`, `PACKAGE_DIRS`: add
   `"plugin_modules/ash_capslock_plugins",` (whole-tree collection errors without
   it: "not named in PACKAGE_DIRS").
3. `automated_security_helper/core/scanner_inventory.py` (the community module
   list that names `ash_betterleaks_plugins`): add
   `"automated_security_helper.plugin_modules.ash_capslock_plugins",`.
4. `tests/unit/plugin_modules/test_scanner_facets_corpus_consistency.py`,
   `CORPORA`: add a `capslock` row and a prep that runs `convert_capslock_output`
   over `tests/test_data/scanners/capslock/schema_derived/positive.json`
   (its native fixture is not SARIF).
5. The shipped-scanner count in three tests (22 becomes 23, plus the others
   already added by the program): `test_scanner_facets_registry_totality.py`,
   `test_scanner_operational_facets_consistency.py` and the corpus agreement test.

### Desk counts

Desk cbc4ff77, repository extract under `/run/user/<uid>/`,
`uv sync --frozen --all-extras --group dev`, `env -i`, `-n 4`:

- Capslock module tests: 53 passed, 0 failed (behavior file plus the new
  sandbox, ignore-path, fixture and facets file).
- Facets families (vocabulary, registry totality, resource-id conformance,
  corpus consistency, operational consistency) plus the module: 561 passed and
  25 failed. Every Capslock-attributable failure is one of the central items
  above (the shipped-scanner counts, `SCANNER_TOOL_TYPES`, the `CORPORA` table
  and its row); the remaining failures are corpus-gate rows of other scanners
  (betterleaks, bandit, gitleaks, opengrep, guarddog, semgrep, trivy, zizmor,
  syft, and others). This change touches none of them; the failures were not
  compared against a base run.
- Whole-tree collect smoke: 74317 of 74362 collected, 1 error: the
  `PACKAGE_DIRS` item above.
- Extract removed and its absence read back.

### Final-review rows (round 2)

Open HIGH, held: no real captured Capslock report exists. The module's fixtures
under `tests/test_data/scanners/capslock/schema_derived/` are derived from the
published proto schema and say so. A capture needs a Go toolchain and a built
`capslock` binary (upstream publishes none), and ASH installs nothing on a scan
host. The test pins the absence of a `captured/` directory. The row stays held
until a capture is made on a venue where installing the tool is approved.

Low-severity rows, no round:

1. The `MAX_MODULES` raise path skips `_post_scan`, while the other raise paths
   call it. Bookkeeping only.
2. `stderr_preference="both"` routes tool stderr into `self.errors` on
   successful runs through the base response handler. The same holds for
   cfn_lint, cfn_nag and npm_audit.
3. `_empty_report()` reads `self.tool_version` before `_pre_scan` on the
   empty-target path. `ToolComponent.version` is optional, so this is cosmetic.
