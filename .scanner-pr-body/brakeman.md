## brakeman: Ruby on Rails static analysis (alpha, opt-in)

### What it scans

`brakeman` over the scan target (source and converted trees) for Rails applications. A
tree with no top-level `app` directory is not a Rails application: Brakeman exits 4 and the
scanner reports a clean no-op. Output is Brakeman's own SARIF, passed through the scanner
template and rated in `_post_process_sarif`.

### Tier

Alpha, community opt-in: the module `ash_brakeman_plugins` must be listed in
`ash_plugin_modules`. A scan that does not list it is unchanged.

### License posture

Brakeman is free for non-commercial use only (Brakeman Public Use License). This is a
deliberate no-install design: ASH ships no install command and no download, the dependency
check names the license and `gem install brakeman`, and listing the module is the
operator's statement that the license covers their use. Only Brakeman's output is committed
(captured fixtures); the tool is not redistributed.

### Facets declared

* Mapping register (`facets`): rule id, severity (confidence level mapped to HIGH, MEDIUM,
  LOW), file path, start line, message are MAPPED; `references` (rule `helpUri`) and `tags`
  (rule warning family) are DROPPED with their native fields; column, resource id and type,
  package fields, CVE and CWE, fingerprints, fix, remediation, snippet are N/A with reasons
  read from the captured SARIF. `extras` is MAPPED (`issue_severity`).
* Operational register: BUNDLED offline, no network, SARIF output, SAST over source code,
  user-installed CLI (no pinned download), severity derived, tool-side ignore file
  (`config/brakeman.ignore`) not honored (ASH passes an empty one), positional identity,
  exit codes 0, 3, 4, community opt-in tier, upstream license cited from the gem's gemspec.

### Findings fixed (RESULTS row: 23/25 applicable rows, 0 MUST, 2 HIGH)

* HIGH, checklist row 24 (no captured fixtures): added
  `tests/test_data/scanners/brakeman/captured/{positive,negative}.sarif` and a README,
  captured from a real Brakeman 8.1.1 run; the unit tests now serve the captures instead of
  hand-built reports. The positive capture holds three results (two `error`, one `warning`),
  so the severity mapping is tested over a captured report.
* HIGH, checklist row 25 (no sandbox-requirements test): a field-by-field test of the
  strict sandbox default.
* The timeout test matched the message wording "timed out after 5"; the scanner says
  "timed out after '5' s", so the pattern now matches the real text.

### Central registration owed (integration lane; not made here)

* `automated_security_helper/utils/scanner_names.py` `SCANNER_TOOL_TYPES`: add
  `"brakeman": "SAST",`
* `tests/unit/plugin_modules/test_scanner_facets_corpus_consistency.py` `CORPORA`: add
  `"brakeman": CorpusSpec("brakeman", sarif=("captured/*.sarif",)),` and change the
  scanner count `22` to `23`.
* `tests/unit/plugin_modules/test_scanner_operational_facets_consistency.py`:
  `_NATIVE_FIXTURES` gets `"brakeman": ("brakeman/captured/positive.sarif", opsf.OutputFormat.SARIF),`
  and the count `22` becomes `23`; `test_scanner_facets_registry_totality.py` count `22` becomes `23`.
* `tests/unit/walked_package.py` `PACKAGE_DIRS`: add `"plugin_modules/ash_brakeman_plugins",`
* `tests/unit/plugin_modules/test_walking_scanners_skip_links_leaving_the_tree.py`:
  `test_every_registered_scanner_has_a_link_handling` needs a `LINK_HANDLING` row and a
  `SCANNER_CLASSES` entry for brakeman. Do NOT register `FOLLOWS_NO_LINK`: measured on
  Brakeman 8.1.1, a symlinked `.rb` file inside `app/controllers` pointing outside the tree
  is read and reported. The scanner needs a link-exclusion unit first (Brakeman has
  `--skip-files`); until then the honest row is a known gap.

### Desk counts (dev-dsk-d14420e2, `-n 4`/`-n 8`, extract removed)

* Brakeman module tests: 58 passed, 0 failed.
* `tests/unit/plugin_modules` + `tests/unit/base` with the central registrations above
  applied to the desk extract only: brakeman's corpus, resource-id conformance,
  operational-consistency and totality families all pass; remaining failures are the
  link-handling row (above) and 20 corpus-consistency failures for the other scanners that
  also fail on main.
* Whole-tree collect: 74362/74407 collected (45 deselected).
