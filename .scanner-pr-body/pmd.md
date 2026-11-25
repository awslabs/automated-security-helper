## Add the PMD alpha scanner plugin

Adds `ash_pmd_plugins`, an opt-in community scanner that runs PMD over the scan target.

### What it scans

`pmd check` over the target with PMD's built-in rule categories, reading PMD's native SARIF
report. The default is the Java security category (`category/java/security.xml`); other
built-in categories can be added through `options.rulesets` and report code-quality
findings. Ruleset files and URLs are refused, because the scanned repository would choose
the rules. PMD is pinned to 7.29.0 (archive digest checked) and needs a Java 11+ runtime on
`PATH`.

### Tier and enablement

Alpha, opt-in: listing `automated_security_helper.plugin_modules.ash_pmd_plugins` in
`ash_plugin_modules` turns the scanner on. A scan that does not list it is unchanged.

### Facets

- `facets`: rule_id, severity, file_path, line_range, column and message are MAPPED from PMD's
  SARIF (`ruleId`, `level` derived from rule priority, `artifactLocation.uri`, `region`,
  `message.text`); extras is MAPPED (`issue_severity`). tags is DROPPED (PMD writes tags on
  the rule, the pipeline reads result tags). resource_id, resource_type, package_*,
  taxonomy_*, fingerprints, fix_available, remediation_text, snippet and references are N/A,
  each with a reason read from the committed capture. resource_id is N/A: findings name a
  source location, not a deployable resource.
- `operational_facets`: offline BUNDLED, no network, strict sandbox; SARIF output; SAST over
  source code; user-installed CLI runtime needing `java`; native severity; both `NOPMD`
  comments (neutralized with `--suppress-marker`) and `@SuppressWarnings("PMD")` (honored)
  declared as tool-side silencing; positional-only identity; no custom rules; exit codes
  {0, 4}; community opt-in tier.

### Findings fixed (RESULTS row for pmd)

- HIGH, checklist row 24: the report tests carried the captures inline. They now read
  committed fixtures `tests/test_data/scanners/pmd/captured/{positive,negative}.sarif` with a
  `captured/README.md` recording argv, version and inputs. The captures are the ones the build
  recorded from PMD 7.29.0; they were not re-captured.
- HIGH, checklist row 25: added `tests/unit/plugin_modules/test_pmd_sandbox_requirements.py`,
  which builds the policy with `build_scanner_policy` and checks the strict default and that the
  JVM and launcher option variables are not passed into the sandbox.
- No MUST was recorded for pmd.

### License posture

PMD's license is BSD-style with an end-user documentation acknowledgement clause and a
no-endorsement clause (LICENSE check: named license, manual). ASH therefore never ships PMD in
the image and never vendors its files; `ash dependencies install` fetches the pinned release
asset from the PMD project, and the plugin README and docs page say so.

### Vocabulary gaps recorded, not worked around

The operational vocabulary has no runtime or provenance value for a module-local pinned
archive installer (`pinned_binary` needs a `TOOL_VERSIONS` entry) and no prerequisite kind for a
Java runtime. The row declares `user_installed_cli` and `external_programs=("java",)`, with the
prerequisite note stating the Java requirement.

### Central registration edits owed (an integration lane serializes these)

None of these is made in this branch:

1. `automated_security_helper/utils/scanner_names.py`, `SCANNER_TOOL_TYPES`: add `"pmd": "SAST",`.
2. `tests/unit/plugin_modules/test_scanner_facets_corpus_consistency.py`, `CORPORA`: add
   `"pmd": CorpusSpec("pmd", sarif=("captured/*.sarif",)),`.
3. `tests/unit/walked_package.py`, `PACKAGE_DIRS`: add `"plugin_modules/ash_pmd_plugins",`
   (whole-tree collection fails without it).
4. The universe counts `== 22` become `== 23` in `test_scanner_facets_registry_totality.py`,
   `test_scanner_operational_facets_consistency.py` and
   `test_scanner_facets_corpus_consistency.py` (this count moves once per landed scanner).

### Desk validation

dev-dsk-d14420e2, repository extract, `uv sync --frozen --all-extras --group dev`, `env -i`,
`CI=1`, `-n 4`, `--basetemp` in the lane, extract removed afterwards.

- pmd test file plus sandbox test: 65 passed, 0 failed.
- Facet families (registry totality, resource-id conformance, corpus consistency, operational
  consistency, both vocabulary meta-tests) with the four central edits above applied to the
  throwaway extract only: 578 passed, 20 failed. The 20 are `test_declared_facets_agree_with_the_observed_corpus`
  cells of other scanners; no pmd cell fails. Without the central edits the families show
  pmd's only failures to be the missing registrations above.
- Whole-tree `pytest --collect-only`: 74328 collected, one collection error, the
  `walked_package.py` registration in item 3.
