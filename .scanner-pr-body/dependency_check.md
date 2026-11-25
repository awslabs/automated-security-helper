## feat(plugins): dependency-check alpha scanner (OWASP Dependency-Check)

### What it scans

OWASP Dependency-Check (Apache-2.0) identifies third-party libraries (Java, .NET,
JavaScript, Python, Ruby, Go and others) in the target and reports the known
vulnerabilities, mostly from the NVD, that match them. It is a Java program, so a
Java runtime must be installed. One run with `--format=SARIF`, one report.

### Tier

Alpha, opt-in: the plugin module `ash_dependency_check_plugins` is off until it is
listed in `ash_plugin_modules`. It is not in the builtin config.

### Facets declared

Both register rows are declared on the class (`facets`, `operational_facets`).

- Mapped: rule_id (CVE id), severity (rated from the rule's CVSS score; every native
  result level is `warning`), file_path, message, taxonomy_cve (the CVE rule id),
  fingerprints (`partialFingerprints["vulnerabilityHash"]`), extras.
- N/A with reason: line_range, column, resource_id and resource_type (findings name a
  dependency file, not a resource), snippet, tags, and the cells whose output was not
  read (package fields, CWE, fix, remediation, references): "output not read; a sample
  run would settle it".
- Operational: content fetch (NVD database), skipped offline (`SKIP_OFFLINE`), sandbox
  network on, SARIF output, SCA, user-installed CLI with Java, success exit codes
  `(0,)`, community opt-in tier, Apache-2.0.

### Fixed from the build review

The review recorded 0 MUST and 2 HIGH findings.

- HIGH, no captured fixture (checklist rows 18 and 24): added
  `tests/test_data/scanners/dependency-check/captured/template-shaped.sarif` and a
  README, plus a test of the severity rating and URI relocation over it. The file is
  NOT a capture from a run: no host with Java was available (a real run also needs
  the NVD download), so it is shaped to the tool's `sarifReport.vsl` template at
  v13.0.0 with invented values, and the README says so. It should be replaced by a
  real capture when one can be produced.
- HIGH, no sandbox-requirements test (row 25): added
  `test_dependency_check_sandbox_requirements.py`, built with `build_scanner_policy`.

### License posture

Apache-2.0 (the scanner license check lists it CLEAN). The design is deliberate: the
release zip is not vendored; a module-local install script downloads the pinned
asset over https, refuses a SHA-256 mismatch and any archive member outside the
install directory, and writes a launcher. Windows is not installed.

### Central registration still owed (serialized by the integration lane)

None of these is in this PR, because they are outside the module:

1. `automated_security_helper/utils/scanner_names.py`, `SCANNER_TOOL_TYPES`: add
   `"dependency-check": "SCA",`.
2. `tests/unit/plugin_modules/test_scanner_facets_corpus_consistency.py`, `CORPORA`:
   add `"dependency-check": CorpusSpec("dependency-check", sarif=("captured/*.sarif",)),`.
3. `tests/unit/walked_package.py`, `PACKAGE_DIRS`: add
   `"plugin_modules/ash_dependency_check_plugins",` (without it, test collection
   fails on the new directory).
4. The universe counts of 22 in `test_scanner_facets_registry_totality.py` and
   `test_scanner_operational_facets_consistency.py` become 23 (each new scanner moves
   them), the literal tool-type table in `tests/unit/utils/test_scanner_tool_types.py`
   gains the entry, and the expected skip-offline set in
   `test_the_service_upload_scanner_is_the_one_that_skips_offline` gains
   `dependency-check`.

### Desk validation

dev-dsk-d14420e2 (a repository extract, `uv sync --frozen --all-extras --group dev`,
`env -i`, `-n 4`): the module's own tests (behavior, template-shaped fixture, sandbox)
all pass. With items 1 to 3 applied locally, the facets registry, corpus agreement
and resource-id conformance, operational consistency and vocabulary families report
no failure naming dependency-check; the only reds are the item 4 literals and the
corpus "declared facets agree" test, which also fails for the other 21 scanners
(for example betterleaks.tags) with 0 verdicts for dependency-check. Whole-tree
collection ran with the local edits to 74,403 collected; the extract was removed.
