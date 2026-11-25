## Add the Bearer SAST scanner as an alpha plugin module

### What it scans

`bearer scan --scanner=sast` over the scan target, in the languages Bearer reads. Findings carry
the rule's CWE ids and Bearer's own severity (critical, high, medium, low, warning). The JSON
report is converted to SARIF by `convert_bearer_report`; Bearer's SARIF writer is not used because
it gives every rule the level `error`.

### Tier

Alpha, opt-in. The scanner loads only when `ash_bearer_plugins` is listed in `ash_plugin_modules`
(or passed with `--ash-plugin-modules`). A scan that does not list the module is unchanged.

### License posture

Bearer is released under the Elastic License 2.0. ASH never installs or redistributes it: there is
no pinned download, no `tool_downloads.py` entry, no Dockerfile step, and `custom_install_commands`
stays empty on purpose. The plugin runs a `bearer` the operator installed and put on PATH. A missing
binary logs the license and the install URL.

### Facets

Both register rows are declared on the class (`facets`, `operational_facets`).

- Mapped: rule id, severity, file path, line range, column, message, CWE taxonomy, fingerprints,
  tags, extras.
- Dropped: references (the rule `helpUri` dies at the flat reader), remediation text, snippet (not
  copied on purpose: the extract quotes scanned code).
- N/A: resource id and type (pure SAST), package fields, CVE taxonomy, fix state.
- Operational: runtime `user_installed_cli`, provenance `user_installed`, exit codes (0, 2),
  severity class native, network none (bundled rules, version check off), silencing layers
  (`bearer.ignore` and `bearer.yml` in the tree are replaced by empty files outside it).

### Findings fixed from the build review

- MUST: `_scan_path` called `self._source_dir()`, which no class in the MRO defined, so every
  committed `scan()` test raised. `_source_dir` is defined on the scanner now.
- HIGH: `test_stderr_is_not_copied_into_errors` could not fail, because the fake replaced
  `_run_subprocess` and the override under test was never the only guard. The scanner now uses the
  base class's `quote_tool_stderr = False` and `unquoted_failure_tool_name`, the local overrides are
  removed, and a new test pairs the guarded case with a positive control that turns the flag on.
- HIGH: no captured-output oracle. Bearer cannot be run in CI under its license, so a committed
  reference report (`tests/test_data/scanners/bearer/reference/positive.json`, hand-written from
  Bearer's report types and labeled as such) and the converter's SARIF over it are added. A new test
  pins the severity mapping and the SARIF validity over that file. A real capture would replace it.

### Open points

- The flags were read from the Bearer 2.x command reference and not run against a binary. The facets
  fingerprint class is `unconfirmed` for the same reason.
- No run with the network blocked has been observed.

### Central registration owed (outside this module, for the integration lane)

One line each:

1. `automated_security_helper/core/scanner_inventory.py`: add
   `"automated_security_helper.plugin_modules.ash_bearer_plugins",` beside the betterleaks entry.
2. `automated_security_helper/utils/scanner_names.py` `SCANNER_TOOL_TYPES`: add `"bearer": "SAST",`.
3. `tests/unit/plugin_modules/test_scanner_facets_corpus_consistency.py` `CORPORA`: add
   `"bearer": CorpusSpec("bearer", sarif=("reference/*.sarif",)),`.
4. The three "22 shipped scanners" counts become 23 (the same corpus-consistency test,
   `test_scanner_facets_registry_totality.py`, `test_scanner_operational_facets_consistency.py`;
   the integration lane's total depends on how many scanners land together).
5. `tests/unit/walked_package.py` `PACKAGE_DIRS`: add `"plugin_modules/ash_bearer_plugins",`.

Applied in the desk extract only (not committed), these five edits turn every bearer-related
failure green.

### Desk validation (dev-dsk-d14420e2, repository extract, uv sync --frozen, env -i, -n 4)

- Bearer module tests plus the facets families (registry totality, resource-id conformance,
  corpus consistency, operational consistency, both vocabulary tests): 573 passed, 20 failed with
  the five edits applied. The 20 are `test_declared_facets_agree_with_the_observed_corpus` for every
  other scanner and they fail identically on an unmodified main extract (20 failed, 494 passed); none
  is bearer's. The bearer corpus cell passes (`-k bearer`: 1 passed).
- Without the five central edits, the failures attributable to this module are the five registration
  rows above (22-to-23 counts, `SCANNER_TOOL_TYPES` KeyError, `PACKAGE_DIRS`, corpus row).
- Whole-tree collect smoke: 74378/74423 collected, 0 errors.
- ruff check and ruff format --check pass (pre-commit, whole tree).
