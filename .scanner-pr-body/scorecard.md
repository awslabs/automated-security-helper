## OpenSSF Scorecard alpha scanner plugin

Adds `ash_scorecard_plugins`, an opt-in community scanner (alpha tier) that runs
`scorecard --repo=github.com/<owner>/<name> --format=json --show-details` and converts the
JSON to SARIF.

### What it scans

The posture of the origin repository as hosted on GitHub (branch protection, code review,
pinned dependencies, token permissions and the other Scorecard checks), not the files ASH
scans. Every finding's message says so. One invocation per scan; the converted target is not
rescored. The repository is `options.repo`, else the `origin` remote in
`<source>/.git/config`; only github.com is supported.

### Tier and gate

Alpha / opt-in: `enabled: false` by default (deliberate: it needs a network and a GitHub
token). It fails the scan, naming the missing piece, when ASH is offline, when none of
`GITHUB_AUTH_TOKEN`, `GITHUB_TOKEN`, `GH_AUTH_TOKEN`, `GH_TOKEN` is set, or when no
github.com repository can be determined. `offline_strategy = SKIP_OFFLINE`,
`success_exit_codes = {0}`, sandbox: network plus the four token names.

### Facets declared

- Result facets (`facets`): rule id = check name, severity = banded check score (0-2 HIGH,
  3-5 MEDIUM, 6-9 LOW; 10 and -1 are not findings), message, fingerprints (computed
  `scorecard/v1`), references (documentation URL), tags, extras. File, line, column,
  resource id, resource type, package, taxonomy, fix, remediation and snippet are n/a with
  reasons. Resource-identity disposition: n/a (a hosted repository locator is not a
  resource id).
- Operational facets (`operational_facets`): content fetch of platform policies, offline
  outcome not_run, sandbox network online, Scorecard JSON output, user-installed CLI,
  derived severity, no tool-side silencing, computed fingerprint, exit codes (0), community
  opt-in tier, auth token plus git checkout prerequisites.
- `tool_type` is SCA with target kind `package_sources`: the register has no hosted-repository
  kind, and this is the nearest fit (recorded in `tool_type_note`).

### Findings fixed (RESULTS row: 2 MUST, 5 HIGH)

- MUST: four `TestOptInGate` tests failed with DID NOT RAISE. `scan()` called `_pre_scan`
  first, which returns False when the gate refuses, so the scan read as skipped. The gate is
  now checked before `_pre_scan` and raises `ScannerError`.
- MUST: `normalize_repo("github.com/o")` returned `github.com/github.com/o`. A GitHub owner has
  no dot or underscore; the owner class is now `[A-Za-z0-9-]`, and tests cover the dotted and
  underscored owners.
- HIGH: the docstring and docs claimed stderr is never copied into `self.errors`, but the
  failure message quoted it. `quote_tool_stderr = False`, stderr goes to the log file only,
  and the exit-code message no longer excerpts it; a canary test pins both.
- HIGH: no sandbox-requirements policy test. Added `test_scorecard_register_and_sandbox.py`
  (network granted online and refused offline, each token name passes through, `GH_HOST` is
  not passed, negative control without the declaration).
- HIGH: docs claimed `ash dependencies install --tool scorecard` downloads a pinned release;
  `tool_downloads.py` has no scorecard entry. The docs, README and the missing-binary message
  now say to install it from the releases page; a test pins that no install command exists.
- Checklist: severity mapping tested at every band edge over a sample result. The sample
  (`tests/unit/plugin_modules/ash_scorecard_plugins/data/`) is schema-derived, NOT a capture:
  a real run needs a GitHub token. Rows 18, 21 and 24 stay partly open for that reason.
- HIGH (existing test red): see the central registration list below; it cannot be fixed
  inside the module.

### License posture

Scorecard is Apache-2.0 (license review: CLEAN, no gate). Nothing is vendored or
redistributed; ASH does not download it yet. The register records the license as "not read"
because no pinned upstream LICENSE read is cited.

### Central edits owed (an integration lane serializes these; none made here)

- `automated_security_helper/core/scanner_inventory.py`: add
  `"automated_security_helper.plugin_modules.ash_scorecard_plugins",` to
  `_VENDORED_SCANNER_PLUGIN_PACKAGES`.
- `automated_security_helper/utils/scanner_names.py`: `"scorecard": "SCA",` in
  `SCANNER_TOOL_TYPES`.
- `tests/unit/plugin_modules/test_scanner_facets_corpus_consistency.py`: a `CorpusSpec` for
  scorecard (the sample result is not a capture; a recorded run is the better input).
- Count assertions of 22 shipped scanners (`test_scanner_facets_registry_totality.py`,
  `test_scanner_operational_facets_consistency.py`) and
  `test_the_service_upload_scanner_is_the_one_that_skips_offline` (scorecard is a second
  `SKIP_OFFLINE` scanner).
- `tests/unit/walked_package.py` `PACKAGE_DIRS`: add `plugin_modules/ash_scorecard_plugins`
  (a whole-tree collect errors without it).
- Other hand-kept lists the guarddog row appears in (`test_list_scanners.py`,
  `test_runtime_patch.py`, `test_scan_phase_community_modules.py`,
  `test_off_host_plugin_modules_from_repo_config.py`).
- Optional: a pinned `scorecard` release table in `utils/tool_downloads.py` (the module
  already calls `pinned_tool_install_commands("scorecard")` and picks it up).

### Final-review rows (round 2)

- HIGH, carried to the integration lane: the central vendored-package registration above
  (`scanner_inventory.py`, `PACKAGE_DIRS`, the count assertions). It is outside this module and
  stays owed to the combined registration pass.
- HIGH, open: the sample result is schema-derived, not a capture. A recorded run needs a GitHub
  token and the `scorecard` binary, neither of which a fix lane holds; rows 18, 21 and 24 close
  when someone with a token records one run and adds its corpus spec.
- Held, not touched: any licensing text (the register keeps the license as "not read").

### Desk validation (dev-dsk-cbc4ff77, env -i, `-n 4`)

- Module tests: 101 passed, 0 failed.
- Facets registry, totality, resource-id conformance, corpus and operational consistency,
  vocabulary families: the failures that remain are the central rows above (plus 20 corpus
  failures that also fail without this module on the same tree).
- Whole-tree `pytest --collect-only -q`: 72863 collected, 1 collection error (the
  `PACKAGE_DIRS` row above).
- ruff format --check and ruff check (locked ruff, pre-commit): green.
