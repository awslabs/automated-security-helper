# feat(plugins): ClamAV alpha scanner plugin

## What it scans

`clamscan --recursive` over the scan target, with symlinks never followed. clamscan has
no SARIF or JSON output, so ASH writes the tool's own `--log` text and builds the SARIF
from it (`parse_clamscan_log`, `detections_to_sarif`). The parser fails closed: a log
with no SCAN SUMMARY block, or whose `Infected files` count disagrees with the `FOUND`
lines, fails the scan instead of reading as clean.

## Tier and enabling

Alpha, opt-in community module: `ash_plugin_modules` must list
`automated_security_helper.plugin_modules.ash_clamav_plugins`. With the module listed the
scanner runs by default; `scanners.clamav.enabled: false` turns it off.

## Facets declared

- Mapping register (`facets`): rule_id, severity, file_path, message, tags, extras mapped
  from the log lines; line_range, column, resource and package facets, taxonomies,
  fingerprints, snippet, references and remediation declared N/A with reasons (the log
  carries a path and a signature name only).
- Operational register (`operational_facets`): no network fetch (BUNDLED offline
  strategy, sandbox network none), output SYNTHESIZED from the log text, runtime
  `user_installed_cli` (`clamscan`), severity CONSTANT (HIGH), no tool-side silencing
  layer, positional-only identity, exit codes (0, 1), tier community opt-in, provenance
  user installed, upstream license `not read` (no pinned upstream LICENSE read was made).

## Findings fixed (RESULTS row, clamav)

- HIGH, `test_stderr_is_not_copied_into_errors` could not fail (the fake replaced
  `_run_subprocess`, so the fold was never exercised). Replaced by a test that calls
  `_process_command_response` directly, a planted control showing the same call with
  `quote_tool_stderr` on does copy stderr, and a declaration check. The hand-written
  override was replaced by the base class's `quote_tool_stderr = False` /
  `unquoted_failure_tool_name = "clamscan"` shape, which also keeps stderr out of the
  failure text.
- Committed tests that failed on current main: four constructed `ClamAVScanner()` without
  a context (main now refuses that), and one asserted the SARIF driver name `ClamAV`
  where the base names it after the scanner (`clamav`). Fixed; every test of the module passes on the desk.
- HIGH, no captured fixture oracle (rows 18/21/24): partly fixed. The log texts moved
  into `tests/test_data/scanners/clamav/documented/` (`positive.txt`, `negative.txt`,
  `positive.sarif`, README), and a test fails when `positive.sarif` drifts from the
  adapter. These are written from ClamAV's source and manual, NOT captured from a
  binary: no clamscan exists on the hosts available, so the directory is named
  `documented`. Rows 18/24 stay unmet until someone captures a real EICAR run.
- HIGH, no install story (rows 11/12): deliberately kept as no-install. ClamAV is a
  system package with a separate signature database; ASH does not download, vendor or
  redistribute it and does not run `freshclam`. `validate_plugin_dependencies` honors
  `dependency_unavailable_reason` and prints the install hint (apt, dnf, brew plus
  `freshclam`), which a test covers. No license gate row exists for the tool; this is a
  design choice, recorded in the module README.

## License posture

Not downloaded, not vendored, not redistributed. The register's upstream license field
reads `not read`.

## Central registration owed (integration lane; NOT made here)

The shared files below are outside this module. With the module on main, the register
tests iterate it automatically, so these fail until the edits land:

1. `automated_security_helper/core/scanner_inventory.py`: add
   `"automated_security_helper.plugin_modules.ash_clamav_plugins"` to the community
   module tuple (the totality tests also expect the count to move from 22 to 23:
   `test_the_enumeration_holds_all_twenty_two_shipped_scanners` and
   `test_the_universe_is_the_twenty_two_shipped_scanners`).
2. `automated_security_helper/utils/scanner_names.py` `SCANNER_TOOL_TYPES`:
   `"clamav": "CUSTOM",`.
3. `automated_security_helper/base/scanner_operational_facets.py`: a
   `TOOL_TYPE_SERVED_BY[ScannerToolType.CUSTOM]` entry and a target kind for malware
   scanning (the module declares `package_sources`, the nearest existing kind, until
   one exists).
4. `tests/unit/plugin_modules/test_scanner_facets_corpus_consistency.py`: a `CorpusSpec`
   row, `"clamav": CorpusSpec("clamav", sarif=("documented/*.sarif",)),`; and
   `test_scanner_operational_facets_consistency.py` `_NATIVE_FIXTURES`.
5. The collect-time guard that names package dirs (`PACKAGE_DIRS` entry for
   `plugin_modules/ash_clamav_plugins`), `config/runtime_patch.py`, config schemas and
   snapshots, as for the other community modules.

## Desk validation (dev-dsk-cbc4ff77, repository extract, uv sync --frozen, env -i)

- Module tests plus the facets families, `-n 4`: 524 passed, 25 failed. Every failure
  is outside this module's own tests: 20 are the corpus-consistency gate that is
  already red on origin/main for the existing scanners (same 20 reproduced on a clean
  origin/main extract), and 5 are the central rows in the list above (counts 22 to 23,
  corpus table, tool-type table, clamav corpus spec).
- Whole-tree collect smoke: 72816 tests collected, 1 collection error: the PACKAGE_DIRS
  guard (item 5).
- Extract removed, absence read back.
- ruff format --check and ruff check green; one noreply identity across the range.
