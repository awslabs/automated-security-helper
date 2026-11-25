## pip-audit alpha scanner plugin

Adds `ash_pip_audit_plugins`, a community (alpha, opt-in) scanner that runs
[pip-audit](https://github.com/pypa/pip-audit) (Apache-2.0, PyPA) over the
Python requirements files in the scan target and reports known vulnerabilities in
each pinned dependency.

### What it scans

- One `pip-audit` run per requirements file (`requirements*.txt`, `*requirements*.txt`,
  any `*.txt` under a `requirements/` directory), pinned `==2.10.1` through uv.
- Every requirement must be pinned to an exact version (`--no-deps --disable-pip`
  keep pip from building anything in the tree). An unpinned requirement or an
  unreachable service fails that file; the run is then not a clean scan.
- pip-audit has no SARIF output, so the adapter converts `--format=json`.
  Findings sit on the requirements line that names the package.
- Every advisory is HIGH (`error`); pip-audit reports no severity.

### Tier and posture

- Alpha, opt-in: enabled by listing `ash_pip_audit_plugins` in `ash_plugin_modules`.
- Needs the network (PyPI or OSV); `network=True` in the sandbox declaration.
  `SKIP_OFFLINE`: offline the scanner reports MISSING with the reason, never a clean audit.
- License posture: Apache-2.0 tool, installed from PyPI at run time by uv; nothing is
  vendored or redistributed. No license or service gate applies.

### Facets declared

Mapping facets (`ScannerFacets`): rule id, severity (constant HIGH), file path, line,
message, package name and version, fingerprints (computed `pip-audit/v1`), tags and
extras are MAPPED; `fix_versions` (fix_available) and rule `helpUri` (references)
are DROPPED with reasons; resource id and type, package path, column, CWE, CVE
taxonomy, remediation text and snippet are N/A with reasons. Operational facets
(`ScannerOperationalFacets`): content fetch of advisory feed and package metadata,
not-run offline, `uv_python` runtime, no provisioned platforms, constant severity,
stable computed fingerprints, success exit codes (0, 1), community opt-in, manifest
prerequisite.

### Findings fixed (RESULTS row 36)

- HIGH: scan() kept its own copy of the pre-fix empty-target probe; it now calls the
  base `_target_is_empty`.
- HIGH, checklist rows 18 and 24: the oracle was synthesized. A real pip-audit 2.10.1
  report over `pyyaml==5.3` and `idna==3.7` is committed under
  `tests/test_data/scanners/pip-audit/captured/` with a README and a `positive.sarif`
  the facets corpus gate reads. The capture showed pip-audit repeating an advisory id
  under one dependency, which produced duplicate results with one fingerprint; the
  converter now keeps one result per package and advisory (test-pinned, with a
  control that the raw capture holds the duplicates).
- HIGH, checklist row 25: `tests/unit/plugin_modules/test_pip_audit_sandbox_requirements.py`
  builds the policy with `build_scanner_policy` (network granted online, refused
  offline, strict default as control, baseline environment only).
- Results now carry `tags` so the tags facet is observable in the flat row.
- No MUST findings were recorded for this row.

### Central registration edits owed (not made here)

These are shared files an integration lane serializes:

1. `automated_security_helper/utils/scanner_names.py` `SCANNER_TOOL_TYPES`: add `"pip-audit": "SCA",`
2. `tests/unit/plugin_modules/test_scanner_facets_corpus_consistency.py` `CORPORA`:
   add `"pip-audit": CorpusSpec("pip-audit", sarif=("captured/*.sarif",)),`
3. `tests/unit/walked_package.py` `PACKAGE_DIRS`: add `plugin_modules/ash_pip_audit_plugins`
   (whole-tree collection errors without it).
4. Universe pins: `tests/unit/plugin_modules/test_scanner_facets_registry_totality.py` and
   `test_scanner_operational_facets_consistency.py` count 22 shipped scanners, and the
   operational consistency test pins the NOT_RUN offline set to `["npm-audit", "snyk-code"]`
   (pip-audit joins it); optionally add pip-audit to `_NATIVE_FIXTURES` there.
5. The usual docs index, CHANGELOG and generated-reference rows for a new community scanner.

### Desk validation

dev-dsk-cbc4ff77, shipped as a repository, `uv sync --frozen --all-extras --group dev`,
`env -i`, `-n 4`: the pip-audit module tests and the sandbox test, 81 passed, 0 failed;
ruff format and check clean. With items 1 and 2 applied in the desk copy only, the
facets corpus gate, registry totality, operational consistency and vocabulary families
read 0 failures for pip-audit; the failures remaining there are the universe-count pins in
item 4 and other scanners' cells not touched by this change. Whole-tree
`--collect-only`: 74342 tests collected, 1 error (item 3). Extract removed, absence read back.
